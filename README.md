# metatavu-secrets-opentofu

OpenTofu provider for [Metatavu Secrets](https://secrets.metatavu.io). A project's infrastructure code uses it to declare the OpenBao access it needs: its environments, its Kubernetes clusters' trust, and its consumers (GitHub Actions environments, Kubernetes namespaces, Expo projects). The secrets server checks and applies them; the provider never handles secret values.

Status: in development.

## Resources (planned)

| Resource | Purpose |
|---|---|
| `msecrets_environment` | A customer/project/environment and its kv mount |
| `msecrets_cluster` | A Kubernetes cluster whose service-account tokens OpenBao trusts |
| `msecrets_github_consumer` | A GitHub repository's environment, logging in with GitHub OIDC |
| `msecrets_kubernetes_consumer` | A namespace's service account, logging in with its token (ESO) |
| `msecrets_expo_consumer` | An EAS project's environment, with a rotated token |

Data sources: `msecrets_meta`, `msecrets_environment`.
