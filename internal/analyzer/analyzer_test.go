package analyzer

import (
	"testing"
	"time"
)

func TestAnalyze_FindsUnusedActions(t *testing.T) {
	a := New()
	role := IAMRole{
		Name: "test-role",
		ARN:  "arn:aws:iam::123456789012:role/test-role",
		Policies: []Policy{
			{
				Name: "test-policy",
				Statements: []Statement{
					{
						Effect:    "Allow",
						Actions:   []string{"s3:GetObject", "s3:PutObject", "s3:DeleteBucket"},
						Resources: []string{"*"},
					},
				},
			},
		},
	}
	events := []CloudTrailEvent{
		{EventTime: time.Now(), EventName: "GetObject", EventSource: "s3.amazonaws.com", UserARN: role.ARN},
		{EventTime: time.Now(), EventName: "PutObject", EventSource: "s3.amazonaws.com", UserARN: role.ARN},
	}
	result := a.Analyze(role, events)
	if len(result.UsedActions) != 2 {
		t.Errorf("expected 2 used actions, got %d", len(result.UsedActions))
	}
	if len(result.UnusedActions) != 1 {
		t.Errorf("expected 1 unused action, got %d", len(result.UnusedActions))
	}
}

func TestRiskScore_WildcardIsHighRisk(t *testing.T) {
	a := New()
	role := IAMRole{
		Name: "wildcard-role",
		ARN:  "arn:aws:iam::123456789012:role/wildcard-role",
		Policies: []Policy{
			{
				Name: "wildcard-policy",
				Statements: []Statement{
					{Effect: "Allow", Actions: []string{"*"}, Resources: []string{"*"}},
				},
			},
		},
	}
	result := a.Analyze(role, []CloudTrailEvent{})
	if result.RiskScore < 70 {
		t.Errorf("expected high risk score, got %d", result.RiskScore)
	}
}