package provider

import (
	"context"
	"strings"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// consumerModel is what every consumer type has. Each resource's own model
// embeds it, with its target's fields.
type consumerModel struct {
	ID             types.String `tfsdk:"id"`
	Environment    types.String `tfsdk:"environment"`
	Name           types.String `tfsdk:"name"`
	Grants         types.Set    `tfsdk:"grants"`
	AcceptFindings types.Map    `tfsdk:"accept_findings"`
	Policy         types.String `tfsdk:"policy"`
	Role           types.String `tfsdk:"role"`
	AuthPath       types.String `tfsdk:"auth_path"`
}

type githubConsumerModel struct {
	consumerModel
	Repository        types.String `tfsdk:"repository"`
	GitHubEnvironment types.String `tfsdk:"github_environment"`
	Writes            types.Set    `tfsdk:"writes"`
}

type kubernetesConsumerModel struct {
	consumerModel
	Cluster        types.String `tfsdk:"cluster"`
	Namespace      types.String `tfsdk:"namespace"`
	ServiceAccount types.String `tfsdk:"service_account"`
}

type expoConsumerModel struct {
	consumerModel
	ProjectID      types.String `tfsdk:"project_id"`
	EASEnvironment types.String `tfsdk:"eas_environment"`
	Variable       types.String `tfsdk:"variable"`
}

// consumerKind is what differs between the consumer resources.
type consumerKind[M any] struct {
	typeName    string
	consumer    string
	description string
	attributes  map[string]schema.Attribute
	common      func(*M) *consumerModel
	toRequest   func(ctx context.Context, m *M, diags *diag.Diagnostics) client.Consumer
	fromServer  func(c *client.Consumer, m *M)
	writes      func(ctx context.Context, m *M, diags *diag.Diagnostics) []string
}

type consumerResource[M any] struct {
	kind   consumerKind[M]
	client *client.Client
}

// NewGitHubConsumerResource is msecrets_github_consumer.
func NewGitHubConsumerResource() resource.Resource {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	return &consumerResource[githubConsumerModel]{kind: consumerKind[githubConsumerModel]{
		typeName: "_github_consumer",
		consumer: client.ConsumerGitHub,
		description: "A GitHub repository's environment that logs in to OpenBao with GitHub's OIDC token, " +
			"through the role `role` on the `github` login. Set the repository's environment variables `VAULT_ADDR` and `VAULT_ROLE` from this resource " +
			"(the integrations/github provider's `github_actions_environment_variable`). It may read `grants`, and create, change and delete `writes` (`infra-` names or `infra-*`).",
		attributes: map[string]schema.Attribute{
			"repository": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "`OWNER/REPO`.",
				PlanModifiers:       replace,
			},
			"github_environment": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The GitHub environment its jobs run in, for example `develop`.",
				PlanModifiers:       replace,
			},
			"writes": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				Default:             setdefault.StaticValue(setOf(nil)),
				MarkdownDescription: "Secrets it may create, change and delete, for credentials its pipeline creates (OpenTofu): `infra-` names, or `infra-*`.",
			},
		},
		common: func(m *githubConsumerModel) *consumerModel { return &m.consumerModel },
		toRequest: func(ctx context.Context, m *githubConsumerModel, diags *diag.Diagnostics) client.Consumer {
			return client.Consumer{
				GitHub: &client.GitHubTarget{Repository: m.Repository.ValueString(), Environment: m.GitHubEnvironment.ValueString()},
				Writes: stringSet(ctx, m.Writes, diags),
			}
		},
		fromServer: func(c *client.Consumer, m *githubConsumerModel) {
			if c.GitHub != nil {
				m.Repository = types.StringValue(c.GitHub.Repository)
				m.GitHubEnvironment = types.StringValue(c.GitHub.Environment)
			}
			m.Writes = setOf(c.Writes)
		},
		writes: func(ctx context.Context, m *githubConsumerModel, diags *diag.Diagnostics) []string {
			return stringSet(ctx, m.Writes, diags)
		},
	}}
}

// NewKubernetesConsumerResource is msecrets_kubernetes_consumer.
func NewKubernetesConsumerResource() resource.Resource {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	return &consumerResource[kubernetesConsumerModel]{kind: consumerKind[kubernetesConsumerModel]{
		typeName: "_kubernetes_consumer",
		consumer: client.ConsumerKubernetes,
		description: "A namespace's service account in a registered cluster that logs in to OpenBao with its token, through the role `role` " +
			"on the cluster's login `auth_path`: the External Secrets Operator's SecretStore uses both. It may read `grants`.",
		attributes: map[string]schema.Attribute{
			"cluster": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "A registered cluster's name (`msecrets_cluster`).",
				PlanModifiers:       replace,
			},
			"namespace": schema.StringAttribute{Required: true, PlanModifiers: replace},
			"service_account": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("openbao-eso"),
				MarkdownDescription: "Defaults to `openbao-eso`.",
				PlanModifiers:       replace,
			},
		},
		common: func(m *kubernetesConsumerModel) *consumerModel { return &m.consumerModel },
		toRequest: func(_ context.Context, m *kubernetesConsumerModel, _ *diag.Diagnostics) client.Consumer {
			return client.Consumer{Kubernetes: &client.KubernetesTarget{
				Cluster:        m.Cluster.ValueString(),
				Namespace:      m.Namespace.ValueString(),
				ServiceAccount: m.ServiceAccount.ValueString(),
			}}
		},
		fromServer: func(c *client.Consumer, m *kubernetesConsumerModel) {
			if c.Kubernetes != nil {
				m.Cluster = types.StringValue(c.Kubernetes.Cluster)
				m.Namespace = types.StringValue(c.Kubernetes.Namespace)
				m.ServiceAccount = types.StringValue(c.Kubernetes.ServiceAccount)
			}
		},
		writes: func(context.Context, *kubernetesConsumerModel, *diag.Diagnostics) []string { return []string{} },
	}}
}

// NewExpoConsumerResource is msecrets_expo_consumer.
func NewExpoConsumerResource() resource.Resource {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	return &consumerResource[expoConsumerModel]{kind: consumerKind[expoConsumerModel]{
		typeName: "_expo_consumer",
		consumer: client.ConsumerExpo,
		description: "An EAS project's environment, whose builds read OpenBao with a token the server rotates into the EAS variable `variable` " +
			"(a token role `role`, with no login). Set the environment's `VAULT_ADDR` and `VAULT_PATH` yourself. It may read `grants`.",
		attributes: map[string]schema.Attribute{
			"project_id": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The EAS project ID (`extra.eas.projectId` in the app's configuration).",
				PlanModifiers:       replace,
			},
			"eas_environment": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "`development`, `preview` or `production`.",
				PlanModifiers:       replace,
				Validators:          []validator.String{stringvalidator.OneOf("development", "preview", "production")},
			},
			"variable": schema.StringAttribute{
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("VAULT_TOKEN"),
				MarkdownDescription: "The EAS variable the token is written to. Defaults to `VAULT_TOKEN`.",
				PlanModifiers:       replace,
			},
		},
		common: func(m *expoConsumerModel) *consumerModel { return &m.consumerModel },
		toRequest: func(_ context.Context, m *expoConsumerModel, _ *diag.Diagnostics) client.Consumer {
			return client.Consumer{Expo: &client.ExpoTarget{
				ProjectID:   m.ProjectID.ValueString(),
				Environment: m.EASEnvironment.ValueString(),
				Variable:    m.Variable.ValueString(),
			}}
		},
		fromServer: func(c *client.Consumer, m *expoConsumerModel) {
			if c.Expo != nil {
				m.ProjectID = types.StringValue(c.Expo.ProjectID)
				m.EASEnvironment = types.StringValue(c.Expo.Environment)
				m.Variable = types.StringValue(c.Expo.Variable)
			}
		},
		writes: func(context.Context, *expoConsumerModel, *diag.Diagnostics) []string { return []string{} },
	}}
}

func (r *consumerResource[M]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + r.kind.typeName
}

func (r *consumerResource[M]) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	keep := []planmodifier.String{stringplanmodifier.UseStateForUnknown()}
	attributes := map[string]schema.Attribute{
		"id": schema.StringAttribute{Computed: true, PlanModifiers: keep},
		"environment": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "`customer/project/environment`.",
			PlanModifiers:       replace,
		},
		"name": schema.StringAttribute{
			Required:            true,
			MarkdownDescription: "Unique in the environment, for example `github-reward-service`. Its OpenBao policy and role are `ms-{c}-{p}-{e}-{name}`.",
			PlanModifiers:       replace,
		},
		"grants": schema.SetAttribute{
			Optional:            true,
			Computed:            true,
			ElementType:         types.StringType,
			Default:             setdefault.StaticValue(setOf(nil)),
			MarkdownDescription: "Secrets it may read.",
		},
		"accept_findings": acceptFindingsAttribute(),
		"policy":          schema.StringAttribute{Computed: true, PlanModifiers: keep},
		"role": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "Its OpenBao role: GitHub's `VAULT_ROLE`, the SecretStore's `role`, or the token role an Expo consumer's tokens are issued from.",
			PlanModifiers:       keep,
		},
		"auth_path": schema.StringAttribute{
			Computed:            true,
			MarkdownDescription: "The login its role is on: `github`, or the cluster's `k8s-{name}`. Empty for an Expo consumer, which has no login.",
			PlanModifiers:       keep,
		},
	}
	for name, attribute := range r.kind.attributes {
		attributes[name] = attribute
	}
	resp.Schema = schema.Schema{MarkdownDescription: r.kind.description, Attributes: attributes}
}

func (r *consumerResource[M]) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configuredClient(req.ProviderData, &resp.Diagnostics)
}

func (r *consumerResource[M]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	common := r.kind.common(&plan)
	accepted, diags := acceptedFindings(ctx, common.AcceptFindings)
	resp.Diagnostics.Append(diags...)
	request := r.kind.toRequest(ctx, &plan, &resp.Diagnostics)
	request.Environment = common.Environment.ValueString()
	request.Name = common.Name.ValueString()
	request.Type = r.kind.consumer
	request.Grants = stringSet(ctx, common.Grants, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	address := request.Environment + ":" + request.Name
	if existing, err := r.client.FindConsumer(ctx, request.Environment, request.Name); err != nil {
		addError(&resp.Diagnostics, "Reading "+request.Environment+"'s consumers failed", err)
		return
	} else if existing != nil {
		resp.Diagnostics.AddError("Consumer exists", address+" already exists; import it: tofu import <address> "+address)
		return
	}
	if _, err := r.client.Execute(ctx, func(ctx context.Context) (*client.Plan, error) { return r.client.PlanConsumer(ctx, request) }, accepted); err != nil {
		addError(&resp.Diagnostics, "Creating "+address+" failed", err)
		return
	}
	created, err := r.client.FindConsumer(ctx, request.Environment, request.Name)
	if err != nil || created == nil {
		if err == nil {
			err = errNotRecorded(address)
		}
		addError(&resp.Diagnostics, "Reading "+address+" failed", err)
		return
	}
	r.fromServer(created, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *consumerResource[M]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := r.kind.common(&state).ID.ValueString()
	consumer, err := r.client.GetConsumer(ctx, id)
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addError(&resp.Diagnostics, "Reading consumer "+id+" failed", err)
		return
	}
	r.fromServer(consumer, &state)
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

// Update changes grants, writes and accept_findings; anything else replaces.
func (r *consumerResource[M]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan, state M
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	common := r.kind.common(&plan)
	accepted, diags := acceptedFindings(ctx, common.AcceptFindings)
	resp.Diagnostics.Append(diags...)
	grants := client.ConsumerGrants{
		Grants: stringSet(ctx, common.Grants, &resp.Diagnostics),
		Writes: r.kind.writes(ctx, &plan, &resp.Diagnostics),
	}
	if resp.Diagnostics.HasError() {
		return
	}
	id := r.kind.common(&state).ID.ValueString()
	address := common.Environment.ValueString() + ":" + common.Name.ValueString()
	if _, err := r.client.Execute(ctx, func(ctx context.Context) (*client.Plan, error) { return r.client.PlanConsumerGrants(ctx, id, grants) }, accepted); err != nil {
		addError(&resp.Diagnostics, "Changing "+address+" failed", err)
		return
	}
	consumer, err := r.client.GetConsumer(ctx, id)
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+address+" failed", err)
		return
	}
	r.fromServer(consumer, &plan)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *consumerResource[M]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state M
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	common := r.kind.common(&state)
	accepted, diags := acceptedFindings(ctx, common.AcceptFindings)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	id := common.ID.ValueString()
	_, err := r.client.Execute(ctx, func(ctx context.Context) (*client.Plan, error) { return r.client.PlanConsumerDelete(ctx, id) }, accepted)
	if err != nil && !client.IsNotFound(err) {
		addError(&resp.Diagnostics, "Removing "+common.Environment.ValueString()+":"+common.Name.ValueString()+" failed", err)
	}
}

// ImportState takes customer/project/environment:name.
func (r *consumerResource[M]) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	environment, name, ok := strings.Cut(req.ID, ":")
	if !ok || strings.Count(environment, "/") != 2 || name == "" {
		resp.Diagnostics.AddError("Unexpected import ID", "Expected customer/project/environment:name, got "+req.ID)
		return
	}
	consumer, err := r.client.FindConsumer(ctx, environment, name)
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+environment+"'s consumers failed", err)
		return
	}
	if consumer == nil {
		resp.Diagnostics.AddError("Consumer not found", req.ID+" doesn't exist")
		return
	}
	if consumer.Type != r.kind.consumer {
		resp.Diagnostics.AddError("Wrong consumer type", req.ID+" is a "+consumer.Type+" consumer")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), consumer.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("accept_findings"), types.MapNull(types.StringType))...)
}

func (r *consumerResource[M]) fromServer(c *client.Consumer, m *M) {
	common := r.kind.common(m)
	common.ID = types.StringValue(c.ID)
	common.Environment = types.StringValue(c.Environment)
	common.Name = types.StringValue(c.Name)
	common.Grants = setOf(c.Grants)
	if c.OpenBao != nil {
		common.Policy = types.StringValue(c.OpenBao.Policy)
		common.Role = types.StringValue(c.OpenBao.Role)
		common.AuthPath = types.StringValue(c.OpenBao.AuthPath)
	}
	r.kind.fromServer(c, m)
}

type notRecordedError string

func (e notRecordedError) Error() string {
	return string(e) + " was applied, but the server has no record of it"
}

func errNotRecorded(address string) error {
	return notRecordedError(address)
}
