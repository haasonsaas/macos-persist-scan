package heuristics

import (
	"path/filepath"
	"strings"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type PathHeuristic struct{}

func NewPathHeuristic() *PathHeuristic {
	return &PathHeuristic{}
}

func (h *PathHeuristic) Name() string {
	return "suspicious_path"
}

func (h *PathHeuristic) Analyze(item *scanner.PersistenceItem) scanner.HeuristicResult {
	result := scanner.HeuristicResult{
		Name:       h.Name(),
		Triggered:  false,
		Score:      0.0,
		Confidence: 0.9,
		Details:    "",
	}

	// Check for suspicious path patterns
	suspiciousPatterns := []struct {
		pattern string
		score   float64
		reason  string
	}{
		{"/tmp/", 0.8, "Binary located in temporary directory"},
		{"/var/tmp/", 0.8, "Binary located in temporary directory"},
		{"/Users/Shared/", 0.6, "Binary in shared user directory (common malware location)"},
		{"/.hidden", 0.7, "Binary in hidden directory"},
		{"/Library/Application Support/", 0.3, "Binary in Application Support (sometimes suspicious)"},
		{"~/Downloads/", 0.5, "Binary in Downloads folder"},
		{"/usr/local/bin/", 0.2, "Binary in user local bin (common for legitimate tools)"},
	}

	programPath := item.Program
	if programPath == "" && item.Path != "" {
		programPath = item.Path
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(programPath, pattern.pattern) {
			result.Triggered = true
			result.Score = pattern.score
			result.Details = pattern.reason
			return result
		}
	}

	// Check for system-level persistence pointing to user directories
	if (item.Mechanism == scanner.MechanismLaunchDaemon || 
	    strings.HasPrefix(item.Path, "/Library/")) &&
	    strings.Contains(programPath, "/Users/") &&
	    !strings.Contains(programPath, "/Users/Shared/") {
		result.Triggered = true
		result.Score = 0.7
		result.Details = "System-level persistence pointing to user directory"
		return result
	}

	// Check for unusually deep nesting
	depth := strings.Count(programPath, "/")
	if depth > 8 {
		result.Triggered = true
		result.Score = 0.5
		result.Details = "Binary located in deeply nested directory"
		return result
	}

	// Check if binary name matches common system binaries but in wrong location
	basename := filepath.Base(programPath)
	systemBinaries := []string{"bash", "sh", "python", "ruby", "perl", "osascript"}
	
	for _, sysbin := range systemBinaries {
		if basename == sysbin && !strings.HasPrefix(programPath, "/usr/") && 
		   !strings.HasPrefix(programPath, "/bin/") &&
		   !strings.HasPrefix(programPath, "/System/") {
			result.Triggered = true
			result.Score = 0.6
			result.Details = "System binary name in non-standard location"
			return result
		}
	}

	return result
}