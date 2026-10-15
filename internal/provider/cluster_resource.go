package provider

import (
	"context"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/client"
	"github.com/hashicorp/terraform-plugin-framework-validators/resourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                     = &clusterResource{}
	_ resource.ResourceWithConfigure        = &clusterResource{}
	_ resource.ResourceWithImportState      = &clusterResource{}
	_ resource.ResourceWithModifyPlan       = &clusterResource{}
	_ resource.ResourceWithConfigValidators = &clusterResource{}
)

// NewClusterResource is msecrets_cluster.
func NewClusterResource() resource.Resource {
	return &clusterResource{}
}

type clusterResource struct {
	client *client.Client
}

type clusterModel struct {
	Name           types.String `tfsdk:"name"`
	Issuer         types.String `tfsdk:"issuer"`
	DiscoveryURL   types.String `tfsdk:"discovery_url"`
	JWKS           types.String `tfsdk:"jwks"`
	PinnedKeys     types.Set    `tfsdk:"pinned_keys"`
	AcceptFindings types.Map    `tfsdk:"accept_findings"`
	Trust          types.String `tfsdk:"trust"`
	Mount          types.String `tfsdk:"mount"`
}

func (r *clusterResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cluster"
}

func (r *clusterResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Kubernetes cluster whose service accounts log in to OpenBao, through the JWT login `k8s-{name}`. " +
			"Give exactly one of `discovery_url`, `jwks` or `pinned_keys`. Registering, changing and removing a cluster need a platform admin. " +
			"Removing one is refused while consumers use it.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Provider and cluster, for example `uks-tuomi-katsy-testing`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"issuer": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The service-account tokens' issuer (`iss`). For UKS, `https://kubernetes.default.svc.cluster.local`.",
			},
			"discovery_url": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "Trust the keys the issuer publishes here (EKS, GKE).",
			},
			"jwks": schema.StringAttribute{
				Optional: true,
				MarkdownDescription: "Trust the RSA keys of this JWKS document, as `kubectl get --raw /openid/v1/jwks` prints it (UKS, k3s). " +
					"It's converted to `pinned_keys` when planning, so a plan shows when the cluster's keys change.",
			},
			"pinned_keys": schema.SetAttribute{
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
				MarkdownDescription: "Trust these PEM public keys. Computed from `jwks` when that's given.",
			},
			"accept_findings": acceptFindingsAttribute(),
			"trust": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`discovery` or `pinned`.",
			},
			"mount": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "The JWT login's mount, `k8s-{name}`: a Kubernetes consumer's `auth_path`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *clusterResource) ConfigValidators(_ context.Context) []resource.ConfigValidator {
	return []resource.ConfigValidator{
		resourcevalidator.ExactlyOneOf(path.MatchRoot("discovery_url"), path.MatchRoot("jwks"), path.MatchRoot("pinned_keys")),
	}
}

func (r *clusterResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configuredClient(req.ProviderData, &resp.Diagnostics)
}

// ModifyPlan works out the trust, and the pinned keys of a JWKS.
func (r *clusterResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.Plan.Raw.IsNull() {
		return
	}
	var plan clusterModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	switch {
	case !plan.DiscoveryURL.IsNull():
		plan.Trust = types.StringValue(client.TrustDiscovery)
		plan.PinnedKeys = types.SetNull(types.StringType)
	case plan.JWKS.IsUnknown():
		plan.Trust = types.StringValue(client.TrustPinned)
		plan.PinnedKeys = types.SetUnknown(types.StringType)
	case !plan.JWKS.IsNull():
		keys, err := client.JWKSToPEM(plan.JWKS.ValueString())
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("jwks"), "Invalid JWKS", err.Error())
			return
		}
		plan.Trust = types.StringValue(client.TrustPinned)
		plan.PinnedKeys = setOf(keys)
	default:
		plan.Trust = types.StringValue(client.TrustPinned)
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, plan)...)
}

func (r *clusterResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan clusterModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	accepted, diags := acceptedFindings(ctx, plan.AcceptFindings)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	if _, err := r.client.GetCluster(ctx, name); err == nil {
		resp.Diagnostics.AddError("Cluster exists", "Cluster "+name+" is already registered; import it: tofu import <address> "+name)
		return
	}
	trust := clusterTrust(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	register := client.Cluster{Name: name, Trust: trust.Trust, Issuer: trust.Issuer, DiscoveryURL: trust.DiscoveryURL, PinnedKeys: trust.PinnedKeys}
	if _, err := r.client.Execute(ctx, func(ctx context.Context) (*client.Plan, error) { return r.client.PlanClusterRegister(ctx, register) }, accepted); err != nil {
		addError(&resp.Diagnostics, "Registering "+name+" failed", err)
		return
	}
	cluster, err := r.client.GetCluster(ctx, name)
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+name+" failed", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, clusterState(cluster, plan))...)
}

func (r *clusterResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state clusterModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	cluster, err := r.client.GetCluster(ctx, state.Name.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+state.Name.ValueString()+" failed", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, clusterState(cluster, state))...)
}

func (r *clusterResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan clusterModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	accepted, diags := acceptedFindings(ctx, plan.AcceptFindings)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := plan.Name.ValueString()
	update := clusterTrust(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.client.Execute(ctx, func(ctx context.Context) (*client.Plan, error) { return r.client.PlanClusterUpdate(ctx, name, update) }, accepted); err != nil {
		addError(&resp.Diagnostics, "Changing "+name+" failed", err)
		return
	}
	cluster, err := r.client.GetCluster(ctx, name)
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+name+" failed", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, clusterState(cluster, plan))...)
}

func (r *clusterResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state clusterModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	accepted, diags := acceptedFindings(ctx, state.AcceptFindings)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	name := state.Name.ValueString()
	_, err := r.client.Execute(ctx, func(ctx context.Context) (*client.Plan, error) { return r.client.PlanClusterDelete(ctx, name) }, accepted)
	if err != nil && !client.IsNotFound(err) {
		addError(&resp.Diagnostics, "Removing "+name+" failed", err)
	}
}

func (r *clusterResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("name"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("accept_findings"), types.MapNull(types.StringType))...)
}

// clusterTrust is the trust a planned cluster asks for.
func clusterTrust(ctx context.Context, plan clusterModel, diags *diag.Diagnostics) client.ClusterUpdate {
	update := client.ClusterUpdate{Issuer: plan.Issuer.ValueString(), Trust: plan.Trust.ValueString()}
	if update.Trust == client.TrustDiscovery {
		update.DiscoveryURL = plan.DiscoveryURL.ValueString()
	} else {
		update.PinnedKeys = stringSet(ctx, plan.PinnedKeys, diags)
	}
	return update
}

// clusterState is the server's cluster, keeping what only the configuration has (jwks, accept_findings).
func clusterState(cluster *client.Cluster, previous clusterModel) clusterModel {
	state := clusterModel{
		Name:           types.StringValue(cluster.Name),
		Issuer:         types.StringValue(cluster.Issuer),
		DiscoveryURL:   types.StringNull(),
		JWKS:           previous.JWKS,
		PinnedKeys:     types.SetNull(types.StringType),
		AcceptFindings: previous.AcceptFindings,
		Trust:          types.StringValue(cluster.Trust),
		Mount:          types.StringValue(cluster.Mount),
	}
	if cluster.Trust == client.TrustDiscovery {
		state.DiscoveryURL = types.StringValue(cluster.DiscoveryURL)
		state.JWKS = types.StringNull()
	} else {
		state.PinnedKeys = setOf(cluster.PinnedKeys)
	}
	return state
}
