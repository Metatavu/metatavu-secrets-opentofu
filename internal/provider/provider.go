// Package provider is the msecrets OpenTofu provider.
package provider

import (
	"context"
	"os"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// DefaultURL is the production server.
const DefaultURL = "https://secrets.metatavu.io"

// Provider configures the client the resources share.
type Provider struct {
	version string
}

// New returns a constructor for the provider at this version.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &Provider{version: version}
	}
}

type providerModel struct {
	URL          types.String `tfsdk:"url"`
	Token        types.String `tfsdk:"token"`
	TokenCommand types.String `tfsdk:"token_command"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
}

func (p *Provider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "msecrets"
	resp.Version = p.version
}

func (p *Provider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Declares a project's OpenBao access through Metatavu Secrets: its environments, its clusters' trust, and its consumers. " +
			"The server checks and applies every change as a plan; the provider never handles secret values.\n\n" +
			"Log in with exactly one of `token`, `token_command`, or `client_id` with `client_secret`. Each setting can come from its environment variable instead; " +
			"when the configuration sets a way to log in, the environment variables for logging in are ignored.",
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "The server. Defaults to `MSECRETS_SERVER_URL`, then `" + DefaultURL + "`.",
			},
			"token": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "An access token (`MSECRETS_TOKEN`). Short-lived: prefer `token_command` for runs that can outlast it.",
			},
			"token_command": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A command that prints an access token and nothing else, run again when the token is about to expire (`MSECRETS_TOKEN_COMMAND`), for example `msecrets auth token`.",
			},
			"client_id": schema.StringAttribute{
				Optional:            true,
				MarkdownDescription: "A confidential client of id.metatavu.fi, for pipelines (`MSECRETS_CLIENT_ID`).",
			},
			"client_secret": schema.StringAttribute{
				Optional:            true,
				Sensitive:           true,
				MarkdownDescription: "The client's secret (`MSECRETS_CLIENT_SECRET`).",
			},
		},
	}
}

func (p *Provider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if config.URL.IsUnknown() || config.Token.IsUnknown() || config.TokenCommand.IsUnknown() || config.ClientID.IsUnknown() || config.ClientSecret.IsUnknown() {
		resp.Diagnostics.AddError("Unknown provider configuration", "The msecrets provider's settings must be known when planning.")
		return
	}
	url := first(config.URL.ValueString(), os.Getenv("MSECRETS_SERVER_URL"), DefaultURL)

	credentials := client.Credentials{
		Token:        config.Token.ValueString(),
		TokenCommand: config.TokenCommand.ValueString(),
		ClientID:     config.ClientID.ValueString(),
		ClientSecret: config.ClientSecret.ValueString(),
	}
	if credentials == (client.Credentials{}) {
		credentials = client.Credentials{
			Token:        os.Getenv("MSECRETS_TOKEN"),
			TokenCommand: os.Getenv("MSECRETS_TOKEN_COMMAND"),
			ClientID:     os.Getenv("MSECRETS_CLIENT_ID"),
			ClientSecret: os.Getenv("MSECRETS_CLIENT_SECRET"),
		}
	}

	c, err := client.New(url, credentials, nil)
	if err != nil {
		resp.Diagnostics.AddError("Can't log in to Metatavu Secrets", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *Provider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewEnvironmentResource,
		NewClusterResource,
		NewGitHubConsumerResource,
		NewKubernetesConsumerResource,
	}
}

func (p *Provider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewMetaDataSource,
		NewEnvironmentDataSource,
	}
}

func first(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
