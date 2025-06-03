package heuristics

import (
	"strings"
	"time"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type BehaviorHeuristic struct{}

func NewBehaviorHeuristic() *BehaviorHeuristic {
	return &BehaviorHeuristic{}
}

func (h *BehaviorHeuristic) Name() string {
	return "suspicious_behavior"
}

func (h *BehaviorHeuristic) Analyze(item *scanner.PersistenceItem) scanner.HeuristicResult {
	result := scanner.HeuristicResult{
		Name:       h.Name(),
		Triggered:  false,
		Score:      0.0,
		Confidence: 0.85,
		Details:    "",
	}

	// Check for persistence without UI that runs constantly
	if item.Mechanism == scanner.MechanismLaunchAgent &&
	   item.RunAtLoad && item.KeepAlive && !item.Disabled {
		// Check if it's likely a background service without UI
		if !h.hasUIIndicators(item) {
			result.Triggered = true
			result.Score = 0.6
			result.Details = "LaunchAgent with KeepAlive and RunAtLoad but no UI components"
			return result
		}
	}

	// Check for recently created persistence (less than 7 days)
	if !item.ModifiedAt.IsZero() {
		age := time.Since(item.ModifiedAt)
		if age < 7*24*time.Hour {
			result.Triggered = true
			result.Score = 0.4
			result.Details = "Recently created persistence item (less than 7 days old)"
			result.Confidence = 0.95
			
			if age < 24*time.Hour {
				result.Score = 0.6
				result.Details = "Very recently created persistence item (less than 24 hours old)"
			}
		}
	}

	// Check for suspicious program arguments
	if len(item.ProgramArgs) > 0 {
		suspiciousArgs := []struct {
			pattern string
			score   float64
			reason  string
		}{
			{"-e", 0.5, "Contains script execution flag"},
			{"base64", 0.7, "Contains base64 encoding/decoding"},
			{"curl", 0.6, "Downloads content from internet"},
			{"wget", 0.6, "Downloads content from internet"},
			{"/dev/null", 0.4, "Redirects output to null device"},
			{"nohup", 0.5, "Runs process immune to hangups"},
			{"eval", 0.7, "Evaluates dynamic code"},
			{"http://", 0.8, "Contains HTTP URL"},
			{"https://", 0.6, "Contains HTTPS URL"},
		}

		argsStr := strings.Join(item.ProgramArgs, " ")
		for _, suspicious := range suspiciousArgs {
			if strings.Contains(strings.ToLower(argsStr), suspicious.pattern) {
				result.Triggered = true
				result.Score = suspicious.score
				result.Details = suspicious.reason
				return result
			}
		}
	}

	// Check for shell script interpreters with inline commands
	if item.Program != "" {
		interpreters := []string{"/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python", "/usr/bin/ruby", "/usr/bin/perl"}
		for _, interpreter := range interpreters {
			if strings.HasSuffix(item.Program, interpreter) && len(item.ProgramArgs) > 1 {
				// Check if arguments contain -c flag (command execution)
				for _, arg := range item.ProgramArgs {
					if arg == "-c" {
						result.Triggered = true
						result.Score = 0.6
						result.Details = "Shell interpreter with inline command execution"
						return result
					}
				}
			}
		}
	}

	// Check for multiple persistence mechanisms from same binary
	// (This would require cross-referencing with other items, simplified here)
	if item.RawData != nil {
		if interval, ok := item.RawData["StartInterval"].(int); ok && interval < 60 {
			result.Triggered = true
			result.Score = 0.5
			result.Details = "Very frequent execution interval (less than 60 seconds)"
			return result
		}
	}

	return result
}

func (h *BehaviorHeuristic) hasUIIndicators(item *scanner.PersistenceItem) bool {
	// Check for common UI-related indicators
	uiIndicators := []string{
		".app/",
		"Contents/MacOS/",
		"LSUIElement",
		"NSUIElement",
		"GUI",
		"Assistant",
		"Helper",
	}

	checkStr := item.Program + " " + item.Label
	if item.RawData != nil {
		for k, v := range item.RawData {
			checkStr += " " + k + " " + string(v.([]byte))
		}
	}

	for _, indicator := range uiIndicators {
		if strings.Contains(checkStr, indicator) {
			return true
		}
	}

	return false
}