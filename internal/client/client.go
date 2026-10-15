// Package client calls the Metatavu Secrets server.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Credentials say how the client gets its access token. Exactly one way is used:
// a fixed token, a command that prints one (run again when it's about to
// expire), or a confidential client's credentials.
type Credentials struct {
	Token        string
	TokenCommand string
	ClientID     string
	ClientSecret string
}

// Client calls one server with one identity.
type Client struct {
	baseURL     string
	http        *http.Client
	credentials Credentials

	mu      sync.Mutex
	token   string
	expires time.Time
	meta    *Meta
}

// New returns a client for the server at baseURL.
func New(baseURL string, credentials Credentials, httpClient *http.Client) (*Client, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 60 * time.Second}
	}
	set := 0
	for _, value := range []string{credentials.Token, credentials.TokenCommand, credentials.ClientID} {
		if value != "" {
			set++
		}
	}
	if set != 1 {
		return nil, errors.New("give exactly one of token, token_command, or client_id with client_secret")
	}
	if credentials.ClientID != "" && credentials.ClientSecret == "" {
		return nil, errors.New("client_id needs client_secret")
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), http: httpClient, credentials: credentials}, nil
}

// IsNotFound tells whether err is the server's 404.
func IsNotFound(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Code == "not_found")
}

// IsCode tells whether err is the server's error with this code.
func IsCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.Code == code
}

// Meta returns the server's discovery document. It needs no token.
func (c *Client) Meta(ctx context.Context) (*Meta, error) {
	c.mu.Lock()
	cached := c.meta
	c.mu.Unlock()
	if cached != nil {
		return cached, nil
	}
	var meta Meta
	if err := c.do(ctx, http.MethodGet, "/v1/meta", nil, &meta, false); err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.meta = &meta
	c.mu.Unlock()
	return &meta, nil
}

// GetEnvironment reads customer/project/environment.
func (c *Client) GetEnvironment(ctx context.Context, path string) (*Environment, error) {
	var env Environment
	return &env, c.do(ctx, http.MethodGet, "/v1/environments/"+path, nil, &env, true)
}

// PlanEnvironment plans creating an environment.
func (c *Client) PlanEnvironment(ctx context.Context, request EnvironmentCreate) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodPost, "/v1/environments", request, &plan, true)
}

// GetConsumer reads a consumer by ID.
func (c *Client) GetConsumer(ctx context.Context, id string) (*Consumer, error) {
	var consumer Consumer
	return &consumer, c.do(ctx, http.MethodGet, "/v1/consumers/"+url.PathEscape(id), nil, &consumer, true)
}

// FindConsumer finds a consumer by its environment and name; nil when there's none.
func (c *Client) FindConsumer(ctx context.Context, environment, name string) (*Consumer, error) {
	var consumers []Consumer
	query := url.Values{"environment": {environment}, "maxResults": {"1000"}}
	if err := c.do(ctx, http.MethodGet, "/v1/consumers?"+query.Encode(), nil, &consumers, true); err != nil {
		return nil, err
	}
	for i := range consumers {
		if consumers[i].Name == name {
			return &consumers[i], nil
		}
	}
	return nil, nil
}

// PlanConsumer plans creating a consumer.
func (c *Client) PlanConsumer(ctx context.Context, request Consumer) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodPost, "/v1/consumers", request, &plan, true)
}

// PlanConsumerGrants plans replacing a consumer's grants and writes.
func (c *Client) PlanConsumerGrants(ctx context.Context, id string, grants ConsumerGrants) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodPut, "/v1/consumers/"+url.PathEscape(id)+"/grants", grants, &plan, true)
}

// PlanConsumerDelete plans removing a consumer.
func (c *Client) PlanConsumerDelete(ctx context.Context, id string) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodDelete, "/v1/consumers/"+url.PathEscape(id), nil, &plan, true)
}

// GetCluster reads a cluster.
func (c *Client) GetCluster(ctx context.Context, name string) (*Cluster, error) {
	var cluster Cluster
	return &cluster, c.do(ctx, http.MethodGet, "/v1/clusters/"+url.PathEscape(name), nil, &cluster, true)
}

// PlanClusterRegister plans registering a cluster.
func (c *Client) PlanClusterRegister(ctx context.Context, cluster Cluster) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodPost, "/v1/clusters", cluster, &plan, true)
}

// PlanClusterUpdate plans replacing a cluster's trust.
func (c *Client) PlanClusterUpdate(ctx context.Context, name string, update ClusterUpdate) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodPut, "/v1/clusters/"+url.PathEscape(name), update, &plan, true)
}

// PlanClusterDelete plans removing a cluster.
func (c *Client) PlanClusterDelete(ctx context.Context, name string) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodDelete, "/v1/clusters/"+url.PathEscape(name), nil, &plan, true)
}

// ApplyPlan applies a plan with the given acceptances.
func (c *Client) ApplyPlan(ctx context.Context, id string, apply PlanApply) (*Plan, error) {
	var plan Plan
	return &plan, c.do(ctx, http.MethodPost, "/v1/plans/"+url.PathEscape(id)+"/apply", apply, &plan, true)
}

// DiscardPlan discards a plan that won't be applied.
func (c *Client) DiscardPlan(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodPost, "/v1/plans/"+url.PathEscape(id)+"/discard", nil, nil, true)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any, authenticated bool) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		token, err := c.accessToken(ctx)
		if err != nil {
			return err
		}
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if response.StatusCode >= 300 {
		apiErr := &APIError{Status: response.StatusCode}
		if json.Unmarshal(raw, apiErr) != nil || apiErr.Message == "" {
			apiErr.Message = fmt.Sprintf("%s %s answered HTTP %d", method, path, response.StatusCode)
		}
		apiErr.Status = response.StatusCode
		return apiErr
	}
	if out != nil && len(raw) > 0 {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// accessToken returns a token that's valid for at least another minute.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.token != "" && time.Until(c.expires) > time.Minute {
		token := c.token
		c.mu.Unlock()
		return token, nil
	}
	c.mu.Unlock()

	var token string
	var err error
	switch {
	case c.credentials.Token != "":
		token = c.credentials.Token
	case c.credentials.TokenCommand != "":
		token, err = runTokenCommand(ctx, c.credentials.TokenCommand)
	default:
		token, err = c.clientCredentials(ctx)
	}
	if err != nil {
		return "", err
	}
	expires := expiry(token)
	c.mu.Lock()
	c.token, c.expires = token, expires
	c.mu.Unlock()
	return token, nil
}

// runTokenCommand runs the command through the shell; it prints the token
// and nothing else to stdout (msecrets auth token).
func runTokenCommand(ctx context.Context, command string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("token_command failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	token := strings.TrimSpace(stdout.String())
	if token == "" || strings.ContainsAny(token, " \n") {
		return "", errors.New("token_command must print one token and nothing else")
	}
	return token, nil
}

func (c *Client) clientCredentials(ctx context.Context) (string, error) {
	meta, err := c.Meta(ctx)
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {c.credentials.ClientID},
		"client_secret": {c.credentials.ClientSecret},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.OIDC.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := c.http.Do(request)
	if err != nil {
		return "", fmt.Errorf("token endpoint: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		// The body may echo the secret, so it isn't shown.
		return "", fmt.Errorf("token endpoint answered HTTP %d for client %s", response.StatusCode, c.credentials.ClientID)
	}
	var parsed struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(response.Body).Decode(&parsed); err != nil {
		return "", err
	}
	return parsed.AccessToken, nil
}

// expiry reads a JWT's exp claim without verifying it (the server verifies);
// a token that isn't a JWT is treated as valid for five minutes.
func expiry(token string) time.Time {
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		if payload, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			var claims struct {
				Exp int64 `json:"exp"`
			}
			if json.Unmarshal(payload, &claims) == nil && claims.Exp > 0 {
				return time.Unix(claims.Exp, 0)
			}
		}
	}
	return time.Now().Add(5 * time.Minute)
}
