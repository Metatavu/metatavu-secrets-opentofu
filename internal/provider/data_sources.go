package provider

import (
	"context"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// NewMetaDataSource is msecrets_meta.
func NewMetaDataSource() datasource.DataSource {
	return &metaDataSource{}
}

type metaDataSource struct {
	client *client.Client
}

type metaModel struct {
	ServerVersion  types.String `tfsdk:"server_version"`
	OpenBaoAddress types.String `tfsdk:"openbao_address"`
	OIDCIssuer     types.String `tfsdk:"oidc_issuer"`
}

func (d *metaDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_meta"
}

func (d *metaDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The server's discovery document: which OpenBao it manages (a consumer's `VAULT_ADDR`).",
		Attributes: map[string]schema.Attribute{
			"server_version":  schema.StringAttribute{Computed: true},
			"openbao_address": schema.StringAttribute{Computed: true, MarkdownDescription: "For example `https://vault.metatavu.io`."},
			"oidc_issuer":     schema.StringAttribute{Computed: true},
		},
	}
}

func (d *metaDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configuredClient(req.ProviderData, &resp.Diagnostics)
}

func (d *metaDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.client, &resp.Diagnostics) {
		return
	}
	meta, err := d.client.Meta(ctx)
	if err != nil {
		addError(&resp.Diagnostics, "Reading the server's discovery document failed", err)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, metaModel{
		ServerVersion:  types.StringValue(meta.ServerVersion),
		OpenBaoAddress: types.StringValue(meta.OpenBao.Address),
		OIDCIssuer:     types.StringValue(meta.OIDC.Issuer),
	})...)
}

// NewEnvironmentDataSource is the data source msecrets_environment.
func NewEnvironmentDataSource() datasource.DataSource {
	return &environmentDataSource{}
}

type environmentDataSource struct {
	client *client.Client
}

type environmentDataModel struct {
	ID     types.String `tfsdk:"id"`
	Kind   types.String `tfsdk:"kind"`
	Status types.String `tfsdk:"status"`
	Mount  types.String `tfsdk:"mount"`
	Access types.List   `tfsdk:"access"`
}

func (d *environmentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_environment"
}

func (d *environmentDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An existing environment, for configurations that don't manage it, such as a pipeline stack that only adds consumers.",
		Attributes: map[string]schema.Attribute{
			"id":     schema.StringAttribute{Required: true, MarkdownDescription: "`customer/project/environment`."},
			"kind":   schema.StringAttribute{Computed: true},
			"status": schema.StringAttribute{Computed: true},
			"mount":  schema.StringAttribute{Computed: true},
			"access": schema.ListAttribute{Computed: true, ElementType: accessType},
		},
	}
}

func (d *environmentDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = configuredClient(req.ProviderData, &resp.Diagnostics)
}

func (d *environmentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	if !requireClient(d.client, &resp.Diagnostics) {
		return
	}
	var config environmentDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	env, err := d.client.GetEnvironment(ctx, config.ID.ValueString())
	if err != nil {
		addError(&resp.Diagnostics, "Reading "+config.ID.ValueString()+" failed", err)
		return
	}
	state := environmentState(env, types.MapNull(types.StringType))
	resp.Diagnostics.Append(resp.State.Set(ctx, environmentDataModel{
		ID:     state.ID,
		Kind:   state.Kind,
		Status: state.Status,
		Mount:  state.Mount,
		Access: state.Access,
	})...)
}
