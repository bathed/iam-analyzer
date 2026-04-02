package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/yourname/iam-analyzer/internal/analyzer"
	"go.uber.org/zap"
)

type IAMClient struct {
	client *iam.Client
	logger *zap.Logger
}

func NewIAMClient(cfg aws.Config, logger *zap.Logger) *IAMClient {
	return &IAMClient{client: iam.NewFromConfig(cfg), logger: logger}
}

func (c *IAMClient) GetRole(ctx context.Context, roleName string) (*analyzer.IAMRole, error) {
	c.logger.Info("Fetching IAM role", zap.String("role", roleName))
	roleOutput, err := c.client.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, fmt.Errorf("failed to get role %s: %w", roleName, err)
	}
	role := &analyzer.IAMRole{
		Name:    *roleOutput.Role.RoleName,
		ARN:     *roleOutput.Role.Arn,
		Created: *roleOutput.Role.CreateDate,
	}
	policies, err := c.getRolePolicies(ctx, roleName)
	if err != nil {
		return nil, err
	}
	role.Policies = policies
	return role, nil
}

func (c *IAMClient) ListRoles(ctx context.Context) ([]string, error) {
	var roleNames []string
	paginator := iam.NewListRolesPaginator(c.client, &iam.ListRolesInput{})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to list roles: %w", err)
		}
		for _, role := range page.Roles {
			roleNames = append(roleNames, *role.RoleName)
		}
	}
	return roleNames, nil
}

func (c *IAMClient) getRolePolicies(ctx context.Context, roleName string) ([]analyzer.Policy, error) {
	var policies []analyzer.Policy
	inline, err := c.getInlinePolicies(ctx, roleName)
	if err != nil {
		return nil, err
	}
	policies = append(policies, inline...)
	managed, err := c.getManagedPolicies(ctx, roleName)
	if err != nil {
		return nil, err
	}
	policies = append(policies, managed...)
	return policies, nil
}

func (c *IAMClient) getInlinePolicies(ctx context.Context, roleName string) ([]analyzer.Policy, error) {
	var policies []analyzer.Policy
	listOutput, err := c.client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, fmt.Errorf("failed to list inline policies: %w", err)
	}
	for _, policyName := range listOutput.PolicyNames {
		policyOutput, err := c.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			continue
		}
		decoded, err := url.QueryUnescape(*policyOutput.PolicyDocument)
		if err != nil {
			continue
		}
		policy, err := parsePolicyDocument(policyName, decoded)
		if err != nil {
			continue
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

func (c *IAMClient) getManagedPolicies(ctx context.Context, roleName string) ([]analyzer.Policy, error) {
	var policies []analyzer.Policy
	listOutput, err := c.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(roleName)})
	if err != nil {
		return nil, fmt.Errorf("failed to list managed policies: %w", err)
	}
	for _, attachedPolicy := range listOutput.AttachedPolicies {
		policyOutput, err := c.client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: attachedPolicy.PolicyArn})
		if err != nil {
			continue
		}
		versionOutput, err := c.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: attachedPolicy.PolicyArn,
			VersionId: policyOutput.Policy.DefaultVersionId,
		})
		if err != nil {
			continue
		}
		decoded, err := url.QueryUnescape(*versionOutput.PolicyVersion.Document)
		if err != nil {
			continue
		}
		policy, err := parsePolicyDocument(*attachedPolicy.PolicyName, decoded)
		if err != nil {
			continue
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

type policyDocument struct {
	Statement []struct {
		Effect   interface{} `json:"Effect"`
		Action   interface{} `json:"Action"`
		Resource interface{} `json:"Resource"`
	} `json:"Statement"`
}

func parsePolicyDocument(name, document string) (analyzer.Policy, error) {
	var doc policyDocument
	if err := json.Unmarshal([]byte(document), &doc); err != nil {
		return analyzer.Policy{}, fmt.Errorf("failed to parse policy: %w", err)
	}
	policy := analyzer.Policy{Name: name}
	for _, stmt := range doc.Statement {
		statement := analyzer.Statement{Effect: fmt.Sprintf("%v", stmt.Effect)}
		statement.Actions = toStringSlice(stmt.Action)
		statement.Resources = toStringSlice(stmt.Resource)
		policy.Statements = append(policy.Statements, statement)
	}
	return policy, nil
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		var result []string
		for _, item := range val {
			result = append(result, fmt.Sprintf("%v", item))
		}
		return result
	default:
		return nil
	}
}