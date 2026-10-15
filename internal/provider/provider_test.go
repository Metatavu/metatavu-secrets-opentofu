package provider

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/fake"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// The tests run OpenTofu against the fake server. OpenTofu's default
// registry is registry.opentofu.org, so the test provider is attached there.
func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC_TERRAFORM_PATH") == "" {
		if tofu, err := exec.LookPath("tofu"); err == nil {
			os.Setenv("TF_ACC_TERRAFORM_PATH", tofu)
		}
	}
	if os.Getenv("TF_ACC_PROVIDER_HOST") == "" {
		os.Setenv("TF_ACC_PROVIDER_HOST", "registry.opentofu.org")
	}
	os.Exit(m.Run())
}

var factories = map[string]func() (tfprotov6.ProviderServer, error){
	"msecrets": providerserver.NewProtocol6WithError(New("test")()),
}

func providerBlock(server *fake.Server) string {
	return fmt.Sprintf(`
provider "msecrets" {
  url   = %q
  token = %q
}
`, server.URL, fake.Token)
}

func jwks(t *testing.T) string {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := base64.RawURLEncoding
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","use":"sig","n":%q,"e":%q}]}`,
		b64.EncodeToString(key.PublicKey.N.Bytes()), b64.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()))
}

func TestEnvironmentNeedsItsFindingsAcceptedAndIsForgottenNotDeleted(t *testing.T) {
	server := fake.New()
	defer server.Close()

	environment := func(accept string) string {
		return providerBlock(server) + `
resource "msecrets_environment" "staging" {
  customer    = "acme"
  project     = "web"
  environment = "staging"
  kind        = "staging"
` + accept + `
}
`
	}
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config:      environment(""),
				ExpectError: regexp.MustCompile(`MS-W036`),
			},
			{
				Config: environment(`  accept_findings = { "MS-W036" = "groups created by hand" }`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("msecrets_environment.staging", "id", "acme/web/staging"),
					resource.TestCheckResourceAttr("msecrets_environment.staging", "mount", "acme/web/staging/kv"),
					resource.TestCheckResourceAttr("msecrets_environment.staging", "access.1.group", "/services/acme/web/staging/hcv/manage"),
				),
			},
			{
				// Environments can't be deleted; a removed block forgets them.
				Config: providerBlock(server) + `
removed {
  from = msecrets_environment.staging
  lifecycle {
    destroy = false
  }
}
`,
			},
		},
	})
	if server.Applied["environment-create"] != 1 || server.Discarded != 1 {
		t.Fatalf("applied %v, discarded %d", server.Applied, server.Discarded)
	}
}

func TestClusterAndConsumers(t *testing.T) {
	server := fake.New()
	defer server.Close()
	server.AddEnvironment("acme/web/staging", "staging")
	firstKeys, secondKeys := jwks(t), jwks(t)

	config := func(keys, grants string) string {
		return providerBlock(server) + fmt.Sprintf(`
resource "msecrets_cluster" "testing" {
  name   = "uks-acme-testing"
  issuer = "https://kubernetes.default.svc.cluster.local"
  jwks   = %q
}

resource "msecrets_kubernetes_consumer" "eso" {
  environment = "acme/web/staging"
  name        = "k8s-uks-testing-eso"
  cluster     = msecrets_cluster.testing.name
  namespace   = "staging"
  grants      = ["runtime-api", "infra-api"]
}

resource "msecrets_github_consumer" "infra" {
  environment        = "acme/web/staging"
  name               = "github-acme-infra"
  repository         = "Metatavu/acme-infra"
  github_environment = "develop"
  grants             = %s
  writes             = ["infra-*"]
}
`, keys, grants)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{
			{
				Config: config(firstKeys, `["build-infra"]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("msecrets_cluster.testing", "trust", "pinned"),
					resource.TestCheckResourceAttr("msecrets_cluster.testing", "mount", "k8s-uks-acme-testing"),
					resource.TestCheckResourceAttr("msecrets_cluster.testing", "pinned_keys.#", "1"),
					resource.TestCheckResourceAttr("msecrets_kubernetes_consumer.eso", "auth_path", "k8s-uks-acme-testing"),
					resource.TestCheckResourceAttr("msecrets_kubernetes_consumer.eso", "service_account", "openbao-eso"),
					resource.TestCheckResourceAttr("msecrets_kubernetes_consumer.eso", "role", "ms-acme-web-staging-k8s-uks-testing-eso"),
					resource.TestCheckResourceAttr("msecrets_github_consumer.infra", "auth_path", "github"),
					resource.TestCheckResourceAttr("msecrets_github_consumer.infra", "writes.0", "infra-*"),
				),
			},
			{
				// The same configuration plans nothing.
				Config:   config(firstKeys, `["build-infra"]`),
				PlanOnly: true,
			},
			{
				// A wrong-kind grant needs accepting.
				Config:      config(firstKeys, `["build-infra", "runtime-api"]`),
				ExpectError: regexp.MustCompile(`MS-W034`),
			},
			{
				// New keys (a recreated cluster) and new grants change in place.
				Config: config(secondKeys, `["build-infra", "build-cloudflare"]`),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("msecrets_github_consumer.infra", "grants.#", "2"),
					func(_ *terraform.State) error {
						if got := server.Applied["cluster-update"]; got != 1 {
							return fmt.Errorf("cluster updates applied: %d", got)
						}
						if got := server.Consumer("acme/web/staging", "github-acme-infra").Grants; strings.Join(got, ",") != "build-cloudflare,build-infra" {
							return fmt.Errorf("grants on the server: %v", got)
						}
						return nil
					},
				),
			},
			{
				ResourceName:            "msecrets_github_consumer.infra",
				ImportState:             true,
				ImportStateId:           "acme/web/staging:github-acme-infra",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"accept_findings"},
			},
		},
		CheckDestroy: func(_ *terraform.State) error {
			if server.Cluster("uks-acme-testing") != nil || server.Consumer("acme/web/staging", "k8s-uks-testing-eso") != nil {
				return fmt.Errorf("the cluster or its consumer is left")
			}
			return nil
		},
	})
}

func TestAStalePlanIsPlannedAgain(t *testing.T) {
	server := fake.New()
	defer server.Close()
	server.AddEnvironment("acme/web/staging", "staging")
	server.StaleOnce = true

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories,
		Steps: []resource.TestStep{{
			Config: providerBlock(server) + `
resource "msecrets_github_consumer" "ui" {
  environment        = "acme/web/staging"
  name               = "github-acme-ui"
  repository         = "Metatavu/acme-ui"
  github_environment = "develop"
  grants             = ["build-ui"]
}
`,
			Check: func(_ *terraform.State) error {
				if server.Applied["consumer-create"] != 1 || server.StaleOnce {
					return fmt.Errorf("applied %v, stale left %v", server.Applied, server.StaleOnce)
				}
				return nil
			},
		}},
	})
}
