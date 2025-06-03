package output

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type TableFormatter struct{}

func (f *TableFormatter) Format(result *scanner.ScanResult) ([]byte, error) {
	var buf bytes.Buffer

	// Create table
	t := table.NewWriter()
	t.SetOutputMirror(&buf)
	t.AppendHeader(table.Row{"Risk", "Mechanism", "Label/Name", "Path", "Program", "Notes"})

	// Sort items by risk level (highest first)
	items := make([]scanner.PersistenceItem, len(result.Items))
	copy(items, result.Items)
	sort.Slice(items, func(i, j int) bool {
		return f.riskLevelToInt(items[i].Risk.Level) > f.riskLevelToInt(items[j].Risk.Level)
	})

	// Add rows
	for _, item := range items {
		riskCell := f.colorizeRisk(item.Risk.Level)
		
		label := item.Label
		if label == "" {
			label = strings.TrimSuffix(item.ID, ".plist")
		}
		
		notes := f.formatNotes(&item)
		
		t.AppendRow(table.Row{
			riskCell,
			item.Mechanism,
			label,
			item.Path,
			item.Program,
			notes,
		})
	}

	// Render table
	t.Render()

	// Add summary
	buf.WriteString("\n")
	buf.WriteString(f.formatSummary(result))

	// Add errors if any
	if len(result.Errors) > 0 {
		buf.WriteString("\n\nErrors encountered during scan:\n")
		for _, err := range result.Errors {
			buf.WriteString(fmt.Sprintf("  - %s: %s\n", err.Mechanism, err.Error))
		}
	}

	// Add permission issues if any
	if len(result.PermissionIssues) > 0 {
		buf.WriteString("\n\nPermission denied for:\n")
		for _, path := range result.PermissionIssues {
			buf.WriteString(fmt.Sprintf("  - %s\n", path))
		}
		buf.WriteString("\nRun with elevated privileges for complete scan.\n")
	}

	return buf.Bytes(), nil
}

func (f *TableFormatter) colorizeRisk(level scanner.RiskLevel) string {
	switch level {
	case scanner.RiskCritical:
		return color.RedString(string(level))
	case scanner.RiskHigh:
		return color.New(color.FgRed, color.Bold).Sprint(string(level))
	case scanner.RiskMedium:
		return color.YellowString(string(level))
	case scanner.RiskLow:
		return color.BlueString(string(level))
	default:
		return color.New(color.FgWhite, color.Faint).Sprint(string(level))
	}
}

func (f *TableFormatter) riskLevelToInt(level scanner.RiskLevel) int {
	switch level {
	case scanner.RiskCritical:
		return 5
	case scanner.RiskHigh:
		return 4
	case scanner.RiskMedium:
		return 3
	case scanner.RiskLow:
		return 2
	default:
		return 1
	}
}

func (f *TableFormatter) formatNotes(item *scanner.PersistenceItem) string {
	var notes []string
	
	if item.RunAtLoad {
		notes = append(notes, "RunAtLoad")
	}
	if item.KeepAlive {
		notes = append(notes, "KeepAlive")
	}
	if item.Disabled {
		notes = append(notes, "Disabled")
	}
	
	// Add top risk reason
	if len(item.Risk.Reasons) > 0 {
		notes = append(notes, item.Risk.Reasons[0])
	}
	
	return strings.Join(notes, ", ")
}

func (f *TableFormatter) formatSummary(result *scanner.ScanResult) string {
	var buf strings.Builder
	
	buf.WriteString(fmt.Sprintf("Scan completed in %s\n", result.Duration.Round(1e6)))
	buf.WriteString(fmt.Sprintf("Total items found: %d\n", result.TotalItems))
	
	if result.TotalItems > 0 {
		buf.WriteString("\nRisk Summary:\n")
		
		levels := []scanner.RiskLevel{
			scanner.RiskCritical,
			scanner.RiskHigh,
			scanner.RiskMedium,
			scanner.RiskLow,
			scanner.RiskInfo,
		}
		
		for _, level := range levels {
			if count, ok := result.RiskSummary[level]; ok && count > 0 {
				buf.WriteString(fmt.Sprintf("  %s: %d\n", f.colorizeRisk(level), count))
			}
		}
	}
	
	return buf.String()
}