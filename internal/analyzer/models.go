package analyzer

import "time"

type IAMRole struct {
	Name     string
	ARN      string
	Created  time.Time
	Policies []Policy
}

type Policy struct {
	Name       string
	Statements []Statement
}

type Statement struct {
	Effect    string
	Actions   []string
	Resources []string
}

type CloudTrailEvent struct {
	EventTime   time.Time
	EventName   string
	EventSource string
	UserARN     string
	Region      string
}

type ResourceUsage struct{
	Action string
	Resources []string
}

type AnalysisResult struct {
	Role            IAMRole
	GrantedActions  []string
	UsedActions     []string
	UnusedActions   []string
	RiskScore       int
	SuggestedPolicy Policy
	LastUsed map[string]time.Time
	ResourceUsage []ResourceUsage
}