package provider

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/Metatavu/metatavu-secrets-opentofu/internal/client"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// acceptFindingsAttribute lets a resource accept the server's findings, each
// with a reason that the server records as an exception.
func acceptFindingsAttribute() schema.MapAttribute {
	return schema.MapAttribute{
		ElementType: types.StringType,
		Optional:    true,
		MarkdownDescription: "Findings (`MS-Wnnn`) the server may report for this resource's changes, each with the reason it's fine. " +
			"The server records an accepted finding as an exception. A change with findings not listed here isn't applied, and the error names them. " +
			"Info-level findings never need accepting.",
	}
}

func acceptedFindings(ctx context.Context, value types.Map) (map[string]string, diag.Diagnostics) {
	accepted := map[string]string{}
	if value.IsNull() || value.IsUnknown() {
		return accepted, nil
	}
	diags := value.ElementsAs(ctx, &accepted, false)
	return accepted, diags
}

// configuredClient is the client the provider configured, for Configure.
func configuredClient(data any, diags *diag.Diagnostics) *client.Client {
	if data == nil {
		return nil
	}
	c, ok := data.(*client.Client)
	if !ok {
		diags.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T", data))
		return nil
	}
	return c
}

// addError explains a failed call or plan.
func addError(diags *diag.Diagnostics, summary string, err error) {
	var findings *client.FindingsError
	if errors.As(err, &findings) {
		diags.AddError(summary+": findings to accept", findings.Error())
		return
	}
	diags.AddError(summary, err.Error())
}

func stringSet(ctx context.Context, value types.Set, diags *diag.Diagnostics) []string {
	out := []string{}
	if value.IsNull() || value.IsUnknown() {
		return out
	}
	diags.Append(value.ElementsAs(ctx, &out, false)...)
	sort.Strings(out)
	return out
}

func setOf(values []string) types.Set {
	elements := make([]string, len(values))
	copy(elements, values)
	sort.Strings(elements)
	set, _ := types.SetValueFrom(context.Background(), types.StringType, elements)
	return set
}

// Server resources are written only through plans, so every resource refuses
// to run without a configured client.
func requireClient(c *client.Client, diags *diag.Diagnostics) bool {
	if c == nil {
		diags.AddError("Provider not configured", "The msecrets provider wasn't configured.")
		return false
	}
	return true
}
