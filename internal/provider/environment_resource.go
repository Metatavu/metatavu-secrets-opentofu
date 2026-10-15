package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                = &environmentResource{}
	_ resource.ResourceWithConfigure   = &environmentResource{}
	_ resource.ResourceWithImportState = &environmentResource{}
)

// NewEnvironmentResource is msecrets_environment.
func NewEnvironmentResource() resource.Resource {
	return &environmentResource{}
}

type environmentResource struct {
	client *client.Client
}

type environmentModel struct {
	ID             types.String `tfsdk:"id"`
	Customer       types.String `tfsdk:"customer"`
	Project        types.String `tfsdk:"project"`
	Environment    types.String `tfsdk:"environment"`
	Kind           types.String `tfsdk:"kind"`
	AcceptFindings types.Map    `tfsdk:"accept_findings"`
	Mount          types.String `tfsdk:"mount"`
	Status         types.String `tfsdk:"status"`
	Access         types.List   `tfsdk:"access"`
}

var accessType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"level":  types.StringType,
	"group":  types.StringType,
	"policy": types.StringType,
}}

func (r *environmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (r *environmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		MarkdownDescription: "An environment, `customer/project/environment`: its kv mount `{c}/{p}/{e}/kv`, and its people's read and manage policies and groups. " +
			"Creating one needs a platform admin. Environments can't be deleted through the server: destroying one fails, and a `removed` block forgets it.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "`customer/project/environment`.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"customer":    schema.StringAttribute{Required: true, PlanModifiers: replace},
			"project":     schema.StringAttribute{Required: true, PlanModifiers: replace},
			"environment": schema.StringAttribute{Required: true, PlanModifiers: replace},
			"kind": schema.StringAttribute{
				Required:            true,
				PlanModifiers:       replace,
				MarkdownDescription: "`local`, `staging`, `beta`, `production` or `other`.",
			},
			"accept_findings": acceptFindingsAttribute(),
			"mount": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"status": schema.StringAttribute{
				Computed:            true,
				MarkdownDescription: "Where the secrets live: `native` for an environment created here.",
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"access": schema.ListAttribute{
				Computed:            true,
				ElementType:         accessType,
				MarkdownDescription: "The id.metatavu.fi groups (`group`) whose members get each level, and its OpenBao policy.",
				PlanModifiers:       []planmodifier.List{listplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *environmentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = configuredClient(req.ProviderData, &resp.Diagnostics)
}

func (r *environmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var plan environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	accepted, diags := acceptedFindings(ctx, plan.AcceptFindings)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	path := plan.Customer.ValueString() + "/" + plan.Project.ValueString() + "/" + plan.Environment.ValueString()
	if existing, err := r.client.GetEnvironment(ctx, path); err == nil && existing != nil {
		resp.Diagnostics.AddError("Environment exists", fmt.Sprintf("%s already exists; import it: tofu import <address> %s", path, path))
		return
	}
	request := client.EnvironmentCreate{
		Customer:    plan.Customer.ValueString(),
		Project:     plan.Project.ValueString(),
		Environment: plan.Environment.ValueString(),
		Kind:        plan.Kind.ValueString(),
	}
	if _, err := r.client.Execute(ctx, func(ctx context.Context) (*client.Plan, error) { return r.client.PlanEnvironment(ctx, request) }, accepted); err != nil {
		addError(&resp.Diagnostics, "Creating "+path+" failed", err)
		return
	}
	env, err := r.client.GetEnvironment(ctx, path)
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+path+" failed", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, environmentState(env, plan.AcceptFindings))...)
}

func (r *environmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	if !requireClient(r.client, &resp.Diagnostics) {
		return
	}
	var state environmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	env, err := r.client.GetEnvironment(ctx, state.ID.ValueString())
	if client.IsNotFound(err) {
		resp.State.RemoveResource(ctx)
		return
	}
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+state.ID.ValueString()+" failed", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, environmentState(env, state.AcceptFindings))...)
}

// Update changes only accept_findings: everything else replaces.
func (r *environmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan environmentModel
	var state environmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	state.AcceptFindings = plan.AcceptFindings
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
}

func (r *environmentResource) Delete(_ context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.Diagnostics.AddError(
		"Environments can't be deleted",
		"Metatavu Secrets doesn't delete environments (their secrets would go with them). To stop managing this one here, "+
			"replace the resource with a removed block:\n\n  removed {\n    from = <address>\n    lifecycle {\n      destroy = false\n    }\n  }",
	)
}

func (r *environmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Unexpected import ID", "Expected customer/project/environment, got "+req.ID)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("customer"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("project"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("environment"), parts[2])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("accept_findings"), types.MapNull(types.StringType))...)
}

func environmentState(env *client.Environment, accept types.Map) environmentModel {
	access := make([]attr.Value, 0, len(env.Access))
	for _, level := range env.Access {
		access = append(access, types.ObjectValueMust(accessType.AttrTypes, map[string]attr.Value{
			"level":  types.StringValue(level.Level),
			"group":  types.StringValue(level.Group),
			"policy": types.StringValue(level.Policy),
		}))
	}
	path := env.Customer + "/" + env.Project + "/" + env.Environment
	return environmentModel{
		ID:             types.StringValue(path),
		Customer:       types.StringValue(env.Customer),
		Project:        types.StringValue(env.Project),
		Environment:    types.StringValue(env.Environment),
		Kind:           types.StringValue(env.Kind),
		AcceptFindings: accept,
		Mount:          types.StringValue(env.Mount),
		Status:         types.StringValue(env.Status),
		Access:         types.ListValueMust(accessType, access),
	}
}
