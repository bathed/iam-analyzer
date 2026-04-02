package report

import (
	"fmt"
	"os"
	"strings"

	"github.com/yourname/iam-analyzer/internal/analyzer"
)

// SaveToHTML — сохраняем красивый HTML отчёт
func (p *Printer) SaveToHTML(result analyzer.AnalysisResult, outputPath string) error {
	html := generateHTML(result)

	if err := os.WriteFile(outputPath, []byte(html), 0644); err != nil {
		return fmt.Errorf("failed to write HTML report: %w", err)
	}

	fmt.Printf("HTML report saved: %s\n", outputPath)
	return nil
}

func generateHTML(result analyzer.AnalysisResult) string {
	riskColor := "#28a745" // зелёный
	if result.RiskScore >= 70 {
		riskColor = "#dc3545" // красный
	} else if result.RiskScore >= 40 {
		riskColor = "#ffc107" // жёлтый
	}

	var unusedRows strings.Builder
	for _, action := range result.UnusedActions {
		danger := ""
		if isDangerous(action) {
			danger = `<span class="badge">DANGEROUS</span>`
		}
		unusedRows.WriteString(fmt.Sprintf(`
			<tr>
				<td>%s %s</td>
			</tr>`, action, danger))
	}

	// Строим строки используемых прав
	var usedRows strings.Builder
	for _, action := range result.UsedActions {
		lastUsed := "never"
		if t, ok := result.LastUsed[action]; ok {
			lastUsed = t.Format("2006-01-02")
		}
		usedRows.WriteString(fmt.Sprintf(`
			<tr>
				<td>%s</td>
				<td>%s</td>
			</tr>`, action, lastUsed))
	}

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>IAM Analyzer - %s</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
		.container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		h1 { color: #333; border-bottom: 2px solid #eee; padding-bottom: 10px; }
		.risk-score { font-size: 48px; font-weight: bold; color: %s; }
		.stats { display: flex; gap: 20px; margin: 20px 0; }
		.stat { background: #f8f9fa; padding: 15px 25px; border-radius: 8px; text-align: center; }
		.stat-number { font-size: 32px; font-weight: bold; color: #333; }
		.stat-label { color: #666; font-size: 14px; }
		table { width: 100%%; border-collapse: collapse; margin-top: 10px; }
		th { background: #333; color: white; padding: 10px; text-align: left; }
		td { padding: 10px; border-bottom: 1px solid #eee; }
		tr:hover { background: #f8f9fa; }
		h2 { margin-top: 30px; color: #333; }
		.badge { background: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; font-size: 12px; margin-left: 8px; }
		.arn { color: #666; font-size: 14px; margin-bottom: 20px; }
	</style>
</head>
<body>
	<div class="container">
		<h1>IAM Analyzer Report</h1>
		<p class="arn">%s</p>

		<div class="risk-score">%d / 100</div>
		<p>Risk Score</p>

		<div class="stats">
			<div class="stat">
				<div class="stat-number">%d</div>
				<div class="stat-label">Total permissions</div>
			</div>
			<div class="stat">
				<div class="stat-number">%d</div>
				<div class="stat-label">Used</div>
			</div>
			<div class="stat">
				<div class="stat-number">%d</div>
				<div class="stat-label">Unused</div>
			</div>
		</div>

		<h2>Unused permissions (remove)</h2>
		<table>
			<tr><th>Permission</th></tr>
			%s
		</table>

		<h2>Used permissions (keep)</h2>
		<table>
			<tr><th>Permission</th><th>Last used</th></tr>
			%s
		</table>
	</div>
</body>
</html>`,
		result.Role.Name,
		riskColor,
		result.Role.ARN,
		result.RiskScore,
		len(result.GrantedActions),
		len(result.UsedActions),
		len(result.UnusedActions),
		unusedRows.String(),
		usedRows.String(),
	)
}