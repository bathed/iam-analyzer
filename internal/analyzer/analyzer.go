package analyzer

import (
	"fmt"
	"strings"
	"time"
)

type Analyzer struct{}

func New() *Analyzer {
	return &Analyzer{}
}

func (a *Analyzer) Analyze(role IAMRole, events []CloudTrailEvent) AnalysisResult {
	result := AnalysisResult{Role: role}

	result.GrantedActions = a.extractGrantedActions(role)
	result.UsedActions = a.extractUsedActions(events)
	result.UnusedActions = a.findUnused(result.GrantedActions, result.UsedActions)
	result.RiskScore = a.calculateRiskScore(result.GrantedActions, result.UnusedActions)
	result.SuggestedPolicy = a.buildSuggestedPolicy(result.UsedActions)
	result.LastUsed = a.extractLastUsed(events)
	result.ResourceUsage = a.extractResourceUsage(events) 


	return result
}

func (a *Analyzer) extractGrantedActions(role IAMRole) []string {
	actionSet := make(map[string]bool)

	for _, policy := range role.Policies {
		for _, stmt := range policy.Statements {
			if strings.EqualFold(stmt.Effect, "Allow") {
				for _, action := range stmt.Actions {
					actionSet[strings.ToLower(action)] = true
				}
			}
		}
	}

	return mapKeys(actionSet)
}

func (a *Analyzer) extractUsedActions(events []CloudTrailEvent) []string {
	actionSet := make(map[string]bool)

	for _, event := range events {
		action := cloudTrailEventToIAMAction(event.EventSource, event.EventName)
		if action != "" {
			actionSet[strings.ToLower(action)] = true
		}
	}

	return mapKeys(actionSet)
}

func (a *Analyzer) findUnused(granted, used []string) []string {
	usedSet := make(map[string]bool)
	for _, action := range used {
		usedSet[strings.ToLower(action)] = true
	}

	var unused []string
	for _, action := range granted {
		if action == "*" || strings.HasSuffix(action, ":*") {
			unused = append(unused, action)
			continue
		}
		if !usedSet[strings.ToLower(action)] {
			unused = append(unused, action)
		}
	}

	return unused
}

func (a *Analyzer) calculateRiskScore(granted, unused []string) int {
	if len(granted) == 0 {
		return 0
	}

	baseScore := (len(unused) * 100) / len(granted)

	wildcardPenalty := 0
	for _, action := range granted {
		if action == "*" {
			wildcardPenalty += 30
		} else if strings.HasSuffix(action, ":*") {
			wildcardPenalty += 15
		}
	}

	dangerPenalty := 0
	dangerKeywords := []string{"delete", "terminate", "destroy", "drop", "remove"}
	for _, action := range unused {
		actionLower := strings.ToLower(action)
		for _, keyword := range dangerKeywords {
			if strings.Contains(actionLower, keyword) {
				dangerPenalty += 5
				break
			}
		}
	}

	score := baseScore + wildcardPenalty + dangerPenalty
	if score > 100 {
		score = 100
	}

	return score
}

func (a *Analyzer) buildSuggestedPolicy(usedActions []string) Policy {
	return Policy{
		Name: "suggested-least-privilege",
		Statements: []Statement{
			{
				Effect:    "Allow",
				Actions:   usedActions,
				Resources: []string{"*"},
			},
		},
	}
}

func cloudTrailEventToIAMAction(eventSource, eventName string) string {
	if eventSource == "" || eventName == "" {
		return ""
	}
	service := strings.TrimSuffix(eventSource, ".amazonaws.com")
	return fmt.Sprintf("%s:%s", service, eventName)
}

func mapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func (a *Analyzer) extractLastUsed(events []CloudTrailEvent) map[string]time.Time{
	lastUsed := make(map[string]time.Time)

	for _, event := range events{
		action := strings.ToLower(cloudTrailEventToIAMAction(event.EventSource, event.EventName))
		if action == ""{
			continue
		}
		if existing, ok := lastUsed[action]; ! ok || event.EventTime.After(existing){
			lastUsed[action] = event.EventTime
		}
	}
	return lastUsed 
}

func (a *Analyzer) extractResourceUsage(events []CloudTrailEvent) []ResourceUsage {
	usageMap := make(map[string]map[string]bool)

	for _, event := range events {
		action := strings.ToLower(cloudTrailEventToIAMAction(event.EventSource, event.EventName))
		if action == "" {
			continue
		}
		if usageMap[action] == nil {
			usageMap[action] = make(map[string]bool)
		}
		if event.Region != "" {
			usageMap[action][event.Region] = true
		}
	}

	var result []ResourceUsage
	for act, resources := range usageMap {
		usage := ResourceUsage{
			Action:    act,
			Resources: mapKeys(resources),
		}
		result = append(result, usage)
	}

	return result
}