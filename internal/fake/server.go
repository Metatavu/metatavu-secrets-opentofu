// Package fake is an in-memory stand-in for the Metatavu Secrets server, for
// the provider's tests. It plans and applies like the server: every write is
// a plan with findings, applied only when they're accepted.
package fake

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/client"
)

// Token is the bearer token the server accepts.
const Token = "test-token"

// Server is the stand-in, with counters the tests check.
type Server struct {
	*httptest.Server

	mu           sync.Mutex
	environments map[string]*client.Environment
	consumers    map[string]*client.Consumer
	clusters     map[string]*client.Cluster
	plans        map[string]*plan
	next         int

	// StaleOnce makes the next apply fail as plan_stale.
	StaleOnce bool
	// Applied and Discarded count plans by kind.
	Applied   map[string]int
	Discarded int
}

type plan struct {
	client.Plan
	apply func()
}

// New starts a stand-in.
func New() *Server {
	s := &Server{
		environments: map[string]*client.Environment{},
		consumers:    map[string]*client.Consumer{},
		clusters:     map[string]*client.Cluster{},
		plans:        map[string]*plan{},
		Applied:      map[string]int{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// AddEnvironment records an environment as if it existed already.
func (s *Server) AddEnvironment(path, kind string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.environments[path] = environment(path, kind)
}

// Consumer returns a consumer's record by environment and name.
func (s *Server) Consumer(environment, name string) *client.Consumer {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.consumers {
		if c.Environment == environment && c.Name == name {
			copied := *c
			return &copied
		}
	}
	return nil
}

// Cluster returns a cluster's record.
func (s *Server) Cluster(name string) *client.Cluster {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c, ok := s.clusters[name]; ok {
		copied := *c
		return &copied
	}
	return nil
}

func environment(path, kind string) *client.Environment {
	parts := strings.Split(path, "/")
	env := &client.Environment{Customer: parts[0], Project: parts[1], Environment: parts[2], Path: path, Kind: kind, Status: "native", Mount: path + "/kv"}
	for _, level := range []string{"read", "manage"} {
		env.Access = append(env.Access, client.AccessLevel{
			Level:  level,
			Group:  "/services/" + path + "/hcv/" + level,
			Policy: strings.ReplaceAll(path, "/", "-") + "-" + level,
		})
	}
	return env
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/v1/meta" {
		write(w, http.StatusOK, client.Meta{
			ServerVersion: "test",
			OIDC:          client.OIDCMeta{Issuer: "https://id.example/realms/test", TokenEndpoint: s.URL + "/token"},
			OpenBao:       client.OpenBaoMeta{Address: "https://vault.example", AuthPath: "oidc", Role: "cli"},
		})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+Token {
		fail(w, http.StatusUnauthorized, "not_authenticated", "a bearer token is required")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	switch {
	case path == "environments" && r.Method == http.MethodPost:
		s.planEnvironment(w, r)
	case strings.HasPrefix(path, "environments/") && r.Method == http.MethodGet:
		if env, ok := s.environments[strings.TrimPrefix(path, "environments/")]; ok {
			write(w, http.StatusOK, env)
		} else {
			fail(w, http.StatusNotFound, "not_found", "no such environment")
		}
	case path == "consumers" && r.Method == http.MethodGet:
		s.listConsumers(w, r)
	case path == "consumers" && r.Method == http.MethodPost:
		s.planConsumer(w, r)
	case strings.HasPrefix(path, "consumers/") && strings.HasSuffix(path, "/grants") && r.Method == http.MethodPut:
		s.planGrants(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "consumers/"), "/grants"))
	case strings.HasPrefix(path, "consumers/") && r.Method == http.MethodGet:
		if c, ok := s.consumers[strings.TrimPrefix(path, "consumers/")]; ok {
			write(w, http.StatusOK, c)
		} else {
			fail(w, http.StatusNotFound, "not_found", "no such consumer")
		}
	case strings.HasPrefix(path, "consumers/") && r.Method == http.MethodDelete:
		s.planConsumerDelete(w, strings.TrimPrefix(path, "consumers/"))
	case path == "clusters" && r.Method == http.MethodPost:
		s.planCluster(w, r)
	case strings.HasPrefix(path, "clusters/") && r.Method == http.MethodGet:
		if c, ok := s.clusters[strings.TrimPrefix(path, "clusters/")]; ok {
			write(w, http.StatusOK, c)
		} else {
			fail(w, http.StatusNotFound, "not_found", "no such cluster")
		}
	case strings.HasPrefix(path, "clusters/") && r.Method == http.MethodPut:
		s.planClusterUpdate(w, r, strings.TrimPrefix(path, "clusters/"))
	case strings.HasPrefix(path, "clusters/") && r.Method == http.MethodDelete:
		s.planClusterDelete(w, strings.TrimPrefix(path, "clusters/"))
	case strings.HasPrefix(path, "plans/") && strings.HasSuffix(path, "/apply"):
		s.apply(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "plans/"), "/apply"))
	case strings.HasPrefix(path, "plans/") && strings.HasSuffix(path, "/discard"):
		if p, ok := s.plans[strings.TrimSuffix(strings.TrimPrefix(path, "plans/"), "/discard")]; ok {
			p.State = "discarded"
			s.Discarded++
			write(w, http.StatusOK, p.Plan)
		} else {
			fail(w, http.StatusNotFound, "not_found", "no such plan")
		}
	default:
		fail(w, http.StatusNotFound, "not_found", r.Method+" "+r.URL.Path)
	}
}

func (s *Server) newPlan(w http.ResponseWriter, kind, target string, changes []client.PlanChange, findings []client.Finding, apply func()) {
	s.next++
	p := &plan{Plan: client.Plan{ID: fmt.Sprintf("pl_%06d", s.next), Kind: kind, Target: target, State: "planned", Changes: changes, Findings: findings}, apply: apply}
	if p.Changes == nil {
		p.Changes = []client.PlanChange{}
	}
	if p.Findings == nil {
		p.Findings = []client.Finding{}
	}
	s.plans[p.ID] = p
	write(w, http.StatusCreated, p.Plan)
}

func (s *Server) apply(w http.ResponseWriter, r *http.Request, id string) {
	p, ok := s.plans[id]
	if !ok || p.State != "planned" {
		fail(w, http.StatusConflict, "conflict", "the plan isn't planned")
		return
	}
	if s.StaleOnce {
		s.StaleOnce = false
		p.State = "failed"
		fail(w, http.StatusConflict, "plan_stale", "OpenBao changed after planning; plan again")
		return
	}
	var request client.PlanApply
	_ = json.NewDecoder(r.Body).Decode(&request)
	accepted := map[string]bool{}
	for _, a := range request.Accept {
		accepted[a.Code] = true
	}
	for _, f := range p.Findings {
		if f.Level != "info" && !accepted[f.Code] {
			fail(w, http.StatusConflict, "findings_not_accepted", "Accept the findings to proceed: "+f.Code)
			return
		}
	}
	p.apply()
	p.State = "applied"
	s.Applied[p.Kind]++
	write(w, http.StatusOK, p.Plan)
}

func (s *Server) planEnvironment(w http.ResponseWriter, r *http.Request) {
	var request client.EnvironmentCreate
	_ = json.NewDecoder(r.Body).Decode(&request)
	path := request.Customer + "/" + request.Project + "/" + request.Environment
	if _, ok := s.environments[path]; ok {
		fail(w, http.StatusConflict, "conflict", path+" already exists")
		return
	}
	s.newPlan(w, "environment-create", path,
		[]client.PlanChange{{System: "records", Action: "create", ObjectType: "environment", Name: path}, {System: "openbao", Action: "create", ObjectType: "kv-mount", Name: path + "/kv"}},
		[]client.Finding{{Code: "MS-W036", Level: "warning", Message: "Create the id.metatavu.fi groups."}},
		func() { s.environments[path] = environment(path, request.Kind) })
}

func (s *Server) listConsumers(w http.ResponseWriter, r *http.Request) {
	environment := r.URL.Query().Get("environment")
	out := []client.Consumer{}
	for _, c := range s.consumers {
		if environment == "" || c.Environment == environment {
			out = append(out, *c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	write(w, http.StatusOK, out)
}

func (s *Server) planConsumer(w http.ResponseWriter, r *http.Request) {
	var request client.Consumer
	_ = json.NewDecoder(r.Body).Decode(&request)
	env, ok := s.environments[request.Environment]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", request.Environment+" doesn't exist")
		return
	}
	for _, c := range s.consumers {
		if c.Environment == request.Environment && c.Name == request.Name {
			fail(w, http.StatusConflict, "conflict", request.Environment+":"+request.Name+" already exists")
			return
		}
	}
	role := "ms-" + strings.ReplaceAll(request.Environment, "/", "-") + "-" + request.Name
	consumer := request
	consumer.ID = fmt.Sprintf("c-%06d", s.next+1)
	consumer.OpenBao = &client.ConsumerOpenBao{Policy: role, Role: role}
	switch request.Type {
	case client.ConsumerGitHub:
		consumer.OpenBao.AuthPath = "github"
	case client.ConsumerKubernetes:
		cluster, ok := s.clusters[request.Kubernetes.Cluster]
		if !ok {
			fail(w, http.StatusBadRequest, "bad_request", "Cluster "+request.Kubernetes.Cluster+" isn't registered; register it first")
			return
		}
		consumer.OpenBao.AuthPath = cluster.Mount
	case client.ConsumerExpo:
		if consumer.Expo.Variable == "" {
			consumer.Expo.Variable = "VAULT_TOKEN"
		}
	}
	if consumer.Writes == nil {
		consumer.Writes = []string{}
	}
	sort.Strings(consumer.Grants)
	sort.Strings(consumer.Writes)
	s.newPlan(w, "consumer-create", env.Path+":"+request.Name,
		[]client.PlanChange{{System: "records", Action: "create", ObjectType: "consumer", Name: env.Path + ":" + request.Name}},
		grantFindings(request.Type, request.Grants),
		func() { s.consumers[consumer.ID] = &consumer })
}

func (s *Server) planGrants(w http.ResponseWriter, r *http.Request, id string) {
	consumer, ok := s.consumers[id]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such consumer")
		return
	}
	var request client.ConsumerGrants
	_ = json.NewDecoder(r.Body).Decode(&request)
	grants, writes := sorted(request.Grants), sorted(request.Writes)
	var changes []client.PlanChange
	if strings.Join(grants, ",") != strings.Join(consumer.Grants, ",") || strings.Join(writes, ",") != strings.Join(consumer.Writes, ",") {
		changes = []client.PlanChange{{System: "records", Action: "update", ObjectType: "consumer", Name: consumer.Environment + ":" + consumer.Name}}
	}
	s.newPlan(w, "consumer-update", consumer.Environment+":"+consumer.Name, changes, grantFindings(consumer.Type, grants),
		func() { consumer.Grants, consumer.Writes = grants, writes })
}

func (s *Server) planConsumerDelete(w http.ResponseWriter, id string) {
	consumer, ok := s.consumers[id]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such consumer")
		return
	}
	s.newPlan(w, "consumer-delete", consumer.Environment+":"+consumer.Name,
		[]client.PlanChange{{System: "records", Action: "delete", ObjectType: "consumer", Name: consumer.Environment + ":" + consumer.Name}},
		nil, func() { delete(s.consumers, id) })
}

func (s *Server) planCluster(w http.ResponseWriter, r *http.Request) {
	var request client.Cluster
	_ = json.NewDecoder(r.Body).Decode(&request)
	if _, ok := s.clusters[request.Name]; ok {
		fail(w, http.StatusConflict, "conflict", "Cluster "+request.Name+" already exists")
		return
	}
	cluster := request
	cluster.Mount = "k8s-" + request.Name
	s.newPlan(w, "cluster-register", request.Name,
		[]client.PlanChange{{System: "records", Action: "create", ObjectType: "cluster", Name: request.Name}},
		nil, func() { s.clusters[cluster.Name] = &cluster })
}

func (s *Server) planClusterUpdate(w http.ResponseWriter, r *http.Request, name string) {
	cluster, ok := s.clusters[name]
	if !ok {
		fail(w, http.StatusNotFound, "not_found", "no such cluster")
		return
	}
	var request client.ClusterUpdate
	_ = json.NewDecoder(r.Body).Decode(&request)
	updated := *cluster
	updated.Trust, updated.Issuer, updated.DiscoveryURL, updated.PinnedKeys = request.Trust, request.Issuer, request.DiscoveryURL, request.PinnedKeys
	var changes []client.PlanChange
	if fmt.Sprint(updated) != fmt.Sprint(*cluster) {
		changes = []client.PlanChange{{System: "records", Action: "update", ObjectType: "cluster", Name: name}}
	}
	s.newPlan(w, "cluster-update", name, changes, nil, func() { s.clusters[name] = &updated })
}

func (s *Server) planClusterDelete(w http.ResponseWriter, name string) {
	if _, ok := s.clusters[name]; !ok {
		fail(w, http.StatusNotFound, "not_found", "no such cluster")
		return
	}
	for _, c := range s.consumers {
		if c.Kubernetes != nil && c.Kubernetes.Cluster == name {
			fail(w, http.StatusConflict, "conflict", "Cluster "+name+" is used by "+c.Environment+":"+c.Name+"; delete those consumers first")
			return
		}
	}
	s.newPlan(w, "cluster-delete", name,
		[]client.PlanChange{{System: "records", Action: "delete", ObjectType: "cluster", Name: name}},
		nil, func() { delete(s.clusters, name) })
}

// grantFindings is a stand-in for the server's: MS-W034 when build and
// runtime secrets go to the wrong kind of consumer.
func grantFindings(kind string, grants []string) []client.Finding {
	var findings []client.Finding
	for _, g := range grants {
		runtime := kind == client.ConsumerKubernetes
		if (runtime && strings.HasPrefix(g, "build-")) || (!runtime && strings.HasPrefix(g, "runtime-")) {
			findings = append(findings, client.Finding{Code: "MS-W034", Level: "warning", Message: g + " is granted to the wrong kind of consumer."})
		}
		findings = append(findings, client.Finding{Code: "MS-W035", Level: "info", Message: g + " doesn't exist yet."})
	}
	return findings
}

func sorted(values []string) []string {
	out := append([]string{}, values...)
	sort.Strings(out)
	return out
}

func write(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func fail(w http.ResponseWriter, status int, code, message string) {
	write(w, status, client.APIError{Status: status, Code: code, Message: message})
}
