# metatavu-secrets-opentofu

OpenTofu provider for [Metatavu Secrets](https://secrets.metatavu.io). A project's infrastructure code uses it to declare the OpenBao access it needs: its environments, its Kubernetes clusters' trust, and its consumers (GitHub Actions environments and Kubernetes namespaces). The secrets server checks every change and applies it as a plan; the provider never handles secret values.

Design: Metatavu Secrets' implementation plan, *OpenTofu Provider* (slice B4).

## Installing

The provider isn't in a public registry. Its source address is `metatavu.io/metatavu/msecrets`, and it's installed from a filesystem mirror:

```sh
scripts/install.sh 0.1.0
```

That puts the release, after checking its checksums, into OpenTofu's implicit local mirror `~/.terraform.d/plugins`, where `tofu init` finds it without any CLI configuration. In GitHub Actions:

```yaml
- uses: Metatavu/metatavu-secrets-opentofu/.github/actions/install@v0.1.0
  with:
    version: 0.1.0
```

```hcl
terraform {
  required_providers {
    msecrets = {
      source  = "metatavu.io/metatavu/msecrets"
      version = "~> 0.1"
    }
  }
}
```

The lock file records the hashes of the platforms that ran `tofu init`. To record others, run `tofu providers lock -fs-mirror=$HOME/.terraform.d/plugins -platform=linux_amd64 -platform=darwin_arm64` with each platform's release installed.

## Logging in

Exactly one of these. Each setting can also come from its environment variable; when the configuration sets a way to log in, those environment variables are ignored.

| Setting | Variable | For |
|---|---|---|
| `token_command` | `MSECRETS_TOKEN_COMMAND` | People: `msecrets auth token`, run again when the token is about to expire, so long applies don't outlast it |
| `client_id`, `client_secret` | `MSECRETS_CLIENT_ID`, `MSECRETS_CLIENT_SECRET` | Pipelines: a confidential client of id.metatavu.fi whose service account is in the environments' `manage` groups |
| `token` | `MSECRETS_TOKEN` | A token you already have; it lives minutes |

`url` (`MSECRETS_SERVER_URL`) defaults to `https://secrets.metatavu.io`.

Creating environments and registering clusters needs a platform admin. Consumers need the environment's `manage` group.

## Resources

| Resource | What it is | Changes in place | Replaces |
|---|---|---|---|
| `msecrets_environment` | `customer/project/environment`, its kv mount, and its people's policies and groups | `accept_findings` | everything else. Destroying fails: environments aren't deleted, so use a `removed` block |
| `msecrets_cluster` | A cluster's JWT login `k8s-{name}`: `discovery_url`, `jwks` (from `kubectl get --raw /openid/v1/jwks`) or `pinned_keys` | trust, keys, issuer | `name` |
| `msecrets_github_consumer` | A repository's GitHub environment, logging in with GitHub OIDC | `grants`, `writes` (`infra-*`) | the environment, name, repository, GitHub environment |
| `msecrets_kubernetes_consumer` | A namespace's service account (default `openbao-eso`) in a registered cluster | `grants` | the environment, name, cluster, namespace, service account |

Data sources: `msecrets_meta` (the OpenBao address, for `VAULT_ADDR`) and `msecrets_environment`.

Imports: an environment by `customer/project/environment`, a cluster by its name, a consumer by `customer/project/environment:name`.

### Findings

The server reports deviations from the agreed practices as findings (`MS-Wnnn`). A change with findings that aren't accepted isn't applied: the provider discards the plan and the error names the findings. Accept the expected ones with a reason, which the server records as an exception:

```hcl
resource "msecrets_environment" "staging" {
  customer    = "tuomi"
  project     = "katsy"
  environment = "staging"
  kind        = "staging"

  accept_findings = {
    "MS-W036" = "The id.metatavu.fi groups were created by hand"
  }
}
```

Info-level findings never need accepting. A plan that goes stale between planning and applying (someone changed OpenBao meanwhile) is planned again once.

### Example

```hcl
resource "msecrets_cluster" "testing" {
  name   = "uks-tuomi-katsy-testing"
  issuer = "https://kubernetes.default.svc.cluster.local"
  jwks   = data.http.jwks.response_body
}

resource "msecrets_kubernetes_consumer" "eso" {
  environment = msecrets_environment.staging.id
  name        = "k8s-uks-testing-eso"
  cluster     = msecrets_cluster.testing.name
  namespace   = "staging"
  grants      = ["runtime-customer-services", "infra-customer-services"]
}

resource "msecrets_github_consumer" "ui" {
  environment        = msecrets_environment.staging.id
  name               = "github-tuomi-katsy-ui"
  repository         = "Metatavu/tuomi-katsy-ui"
  github_environment = "develop"
  grants             = ["build-ui"]
}

# The repository's GitHub environment variables, with the integrations/github provider
resource "github_actions_environment_variable" "vault_role" {
  repository    = "tuomi-katsy-ui"
  environment   = "develop"
  variable_name = "VAULT_ROLE"
  value         = msecrets_github_consumer.ui.role
}
```

## Developing

```sh
go test ./...
```

The resource tests run OpenTofu (`tofu` on the `PATH`, or `TF_ACC_TERRAFORM_PATH`) against `internal/fake`, an in-memory stand-in for the server that plans and applies like it.

Releases: push a tag `vX.Y.Z`. The Release workflow tests and runs GoReleaser, which puts zips and checksums on the GitHub release.
