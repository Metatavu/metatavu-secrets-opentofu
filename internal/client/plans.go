package client

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Planner makes a plan; called again when a plan goes stale before it's applied.
type Planner func(ctx context.Context) (*Plan, error)

// Execute plans, checks the plan's findings against accepted (code → reason),
// and applies it. Findings at the info level never need accepting. A plan with
// unaccepted findings is discarded and nothing changes. A plan that went stale
// between planning and applying is planned again once. An empty plan is
// discarded, not applied.
func (c *Client) Execute(ctx context.Context, plan Planner, accepted map[string]string) (*Plan, error) {
	for attempt := 0; ; attempt++ {
		planned, err := plan(ctx)
		if err != nil {
			return nil, err
		}
		if len(planned.Changes) == 0 {
			_ = c.DiscardPlan(ctx, planned.ID)
			return planned, nil
		}
		if unaccepted := Unaccepted(planned.Findings, accepted); len(unaccepted) > 0 {
			_ = c.DiscardPlan(ctx, planned.ID)
			return nil, &FindingsError{Plan: planned, Findings: unaccepted}
		}
		applied, err := c.ApplyPlan(ctx, planned.ID, acceptances(planned.Findings, accepted))
		if err != nil && IsCode(err, "plan_stale") && attempt == 0 {
			continue
		}
		return applied, err
	}
}

// Unaccepted returns the findings above the info level that accepted doesn't list.
func Unaccepted(findings []Finding, accepted map[string]string) []Finding {
	var out []Finding
	for _, finding := range findings {
		if finding.Level == "info" {
			continue
		}
		if _, ok := accepted[finding.Code]; !ok {
			out = append(out, finding)
		}
	}
	return out
}

// acceptances lists only the accepted codes the plan has, so that an apply
// records exceptions for what it actually accepted.
func acceptances(findings []Finding, accepted map[string]string) PlanApply {
	seen := map[string]bool{}
	var apply PlanApply
	for _, finding := range findings {
		reason, ok := accepted[finding.Code]
		if !ok || seen[finding.Code] {
			continue
		}
		seen[finding.Code] = true
		apply.Accept = append(apply.Accept, FindingAcceptance{Code: finding.Code, Reason: reason})
	}
	sort.Slice(apply.Accept, func(i, j int) bool { return apply.Accept[i].Code < apply.Accept[j].Code })
	return apply
}

// FindingsError is a plan whose findings weren't accepted.
type FindingsError struct {
	Plan     *Plan
	Findings []Finding
}

func (e *FindingsError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "the server's plan for %s has findings to accept; nothing was changed.\n", e.Plan.Target)
	for _, finding := range e.Findings {
		fmt.Fprintf(&b, "\n%s (%s): %s", finding.Code, finding.Level, finding.Message)
		if finding.Practice != "" {
			fmt.Fprintf(&b, "\n  Practice: %s", finding.Practice)
		}
	}
	b.WriteString("\n\nIf they're expected, accept them in the resource with a reason, for example:\n  accept_findings = {\n")
	for _, finding := range e.Findings {
		fmt.Fprintf(&b, "    %q = \"<why this is fine>\"\n", finding.Code)
	}
	b.WriteString("  }")
	return b.String()
}
