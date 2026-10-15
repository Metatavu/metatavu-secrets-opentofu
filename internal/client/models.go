package client

// The parts of the Metatavu Secrets API (metatavu-secrets-api-spec, swagger.yaml)
// the provider uses. Names follow the spec.

// Meta is the server's discovery document.
type Meta struct {
	ServerVersion string      `json:"serverVersion"`
	OIDC          OIDCMeta    `json:"oidc"`
	OpenBao       OpenBaoMeta `json:"openbao"`
}

// OIDCMeta tells where to get tokens.
type OIDCMeta struct {
	Issuer        string `json:"issuer"`
	ClientID      string `json:"clientId"`
	TokenEndpoint string `json:"tokenEndpoint"`
}

// OpenBaoMeta tells which OpenBao the server manages.
type OpenBaoMeta struct {
	Address  string `json:"address"`
	AuthPath string `json:"authPath"`
	Role     string `json:"role"`
}

// Environment is customer/project/environment and its kv mount.
type Environment struct {
	Customer    string        `json:"customer"`
	Project     string        `json:"project"`
	Environment string        `json:"environment"`
	Path        string        `json:"path,omitempty"`
	Kind        string        `json:"kind"`
	Status      string        `json:"status,omitempty"`
	Mount       string        `json:"mount,omitempty"`
	Access      []AccessLevel `json:"access,omitempty"`
}

// AccessLevel is a people group's level in an environment.
type AccessLevel struct {
	Level  string `json:"level"`
	Group  string `json:"group"`
	Policy string `json:"policy"`
}

// EnvironmentCreate plans an environment.
type EnvironmentCreate struct {
	Customer    string `json:"customer"`
	Project     string `json:"project"`
	Environment string `json:"environment"`
	Kind        string `json:"kind"`
}

// Consumer types
const (
	ConsumerGitHub     = "github-environment"
	ConsumerKubernetes = "kubernetes"
	ConsumerExpo       = "expo"
)

// Consumer reads, and for GitHub may write, an environment's secrets.
type Consumer struct {
	ID          string            `json:"id,omitempty"`
	Environment string            `json:"environment"`
	Name        string            `json:"name"`
	Type        string            `json:"type"`
	GitHub      *GitHubTarget     `json:"github,omitempty"`
	Kubernetes  *KubernetesTarget `json:"kubernetes,omitempty"`
	Grants      []string          `json:"grants"`
	Writes      []string          `json:"writes,omitempty"`
	OpenBao     *ConsumerOpenBao  `json:"openbao,omitempty"`
}

// GitHubTarget is a repository's GitHub environment.
type GitHubTarget struct {
	Repository  string `json:"repository"`
	Environment string `json:"environment"`
}

// KubernetesTarget is a namespace's service account in a registered cluster.
type KubernetesTarget struct {
	Cluster        string `json:"cluster"`
	Namespace      string `json:"namespace"`
	ServiceAccount string `json:"serviceAccount"`
}

// ConsumerOpenBao is the consumer's objects in OpenBao.
type ConsumerOpenBao struct {
	Policy   string `json:"policy"`
	AuthPath string `json:"authPath,omitempty"`
	Role     string `json:"role,omitempty"`
}

// ConsumerGrants replaces what a consumer may read, and write.
type ConsumerGrants struct {
	Grants []string `json:"grants"`
	Writes []string `json:"writes"`
}

// Cluster trusts
const (
	TrustDiscovery = "discovery"
	TrustPinned    = "pinned"
)

// Cluster is a Kubernetes cluster whose service accounts log in to OpenBao.
type Cluster struct {
	Name         string   `json:"name"`
	Mount        string   `json:"mount,omitempty"`
	Trust        string   `json:"trust"`
	Issuer       string   `json:"issuer"`
	DiscoveryURL string   `json:"discoveryUrl,omitempty"`
	PinnedKeys   []string `json:"pinnedKeys,omitempty"`
}

// ClusterUpdate replaces a cluster's trust.
type ClusterUpdate struct {
	Trust        string   `json:"trust"`
	Issuer       string   `json:"issuer"`
	DiscoveryURL string   `json:"discoveryUrl,omitempty"`
	PinnedKeys   []string `json:"pinnedKeys,omitempty"`
}

// Plan is a change the server computed; applying executes exactly it.
type Plan struct {
	ID       string       `json:"id"`
	Kind     string       `json:"kind"`
	Target   string       `json:"target"`
	State    string       `json:"state"`
	Changes  []PlanChange `json:"changes"`
	Findings []Finding    `json:"findings"`
}

// PlanChange is one change to one object.
type PlanChange struct {
	System     string   `json:"system"`
	Action     string   `json:"action"`
	ObjectType string   `json:"objectType"`
	Name       string   `json:"name"`
	Fields     []string `json:"fields,omitempty"`
}

// Finding is a deviation from the agreed practices.
type Finding struct {
	Code     string `json:"code"`
	Level    string `json:"level"`
	Message  string `json:"message"`
	Practice string `json:"practice,omitempty"`
}

// PlanApply accepts findings for an apply.
type PlanApply struct {
	Accept []FindingAcceptance `json:"accept,omitempty"`
}

// FindingAcceptance accepts one finding with a reason.
type FindingAcceptance struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// APIError is the server's error body.
type APIError struct {
	Status  int    `json:"status"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	return e.Code + ": " + e.Message
}
