package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/yourname/iam-analyzer/internal/analyzer"
)

type Printer struct{}

func New() *Printer {
	return &Printer{}
}

func (p *Printer) PrintToTerminal(result analyzer.AnalysisResult) {
	fmt.Println()
	fmt.Println("================================================")
	fmt.Printf("  IAM ANALYZER - %s\n", result.Role.Name)
	fmt.Println("================================================")
	fmt.Printf("\nRole:    %s\n", result.Role.Name)
	fmt.Printf("ARN:     %s\n", result.Role.ARN)

	riskLabel, riskIcon := getRiskLabel(result.RiskScore)
	fmt.Printf("Risk Score: %d/100 %s %s\n\n", result.RiskScore, riskIcon, riskLabel)

	fmt.Printf("Total permissions:    %d\n", len(result.GrantedActions))
	fmt.Printf("Used:                 %d\n", len(result.UsedActions))
	fmt.Printf("Unused:               %d\n\n", len(result.UnusedActions))

	if len(result.UsedActions) > 0 {
		fmt.Println("Used permissions (keep):")
		for _, action := range result.UsedActions {
			lastUsed := "never"
			if t, ok := result.LastUsed[action]; ok {
				lastUsed = t.Format("2006-01-02")
			}
			fmt.Printf("  + %-40s last used: %s\n", action, lastUsed)
		}
	}

	if len(result.UnusedActions) > 0 {
		fmt.Println("\nUnused permissions (remove):")
		for _, action := range result.UnusedActions {
			danger := ""
			if isDangerous(action) {
				danger = " DANGEROUS!"
			}
			fmt.Printf("  - %s%s\n", action, danger)
		}
	}

	fmt.Println("\n================================================")
}

func (p *Printer) SaveToJSON(result analyzer.AnalysisResult, outputPath string) error {
	report := map[string]interface{}{
		"role":            map[string]interface{}{"name": result.Role.Name, "arn": result.Role.ARN},
		"risk_score":      result.RiskScore,
		"granted_actions": result.GrantedActions,
		"used_actions":    result.UsedActions,
		"unused_actions":  result.UnusedActions,
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}
	if err := os.WriteFile(outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}
	fmt.Printf("Report saved: %s\n", outputPath)
	return nil
}

func getRiskLabel(score int) (string, string) {
	switch {
	case score >= 70:
		return "HIGH - remove unused permissions immediately!", "🔴"
	case score >= 40:
		return "MEDIUM - consider cleaning up", "🟡"
	default:
		return "LOW - looking good", "🟢"
	}
}

func isDangerous(action string) bool {
	dangerous := []string{"delete", "terminate", "destroy", "drop", "remove"}
	actionLower := strings.ToLower(action)
	for _, d := range dangerous {
		if strings.Contains(actionLower, d) {
			return true
		}
	}
	return false
}