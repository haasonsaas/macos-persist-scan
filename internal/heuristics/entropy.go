package heuristics

import (
	"math"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type EntropyHeuristic struct{}

func NewEntropyHeuristic() *EntropyHeuristic {
	return &EntropyHeuristic{}
}

func (h *EntropyHeuristic) Name() string {
	return "name_entropy"
}

func (h *EntropyHeuristic) Analyze(item *scanner.PersistenceItem) scanner.HeuristicResult {
	result := scanner.HeuristicResult{
		Name:       h.Name(),
		Triggered:  false,
		Score:      0.0,
		Confidence: 0.7,
		Details:    "",
	}

	// Analyze label/name entropy
	nameToCheck := item.Label
	if nameToCheck == "" {
		nameToCheck = filepath.Base(item.Path)
	}

	// Check for known legitimate patterns
	if h.isLegitimateNaming(nameToCheck) {
		return result
	}

	// Check for suspicious patterns
	if h.isSuspiciousNaming(nameToCheck) {
		result.Triggered = true
		result.Score = 0.7
		result.Details = "Name appears to mimic Apple naming conventions"
		return result
	}

	// Calculate entropy
	entropy := h.calculateEntropy(nameToCheck)
	
	// High entropy indicates randomness
	if entropy > 4.5 {
		result.Triggered = true
		result.Score = 0.6
		result.Details = "High entropy in name suggests randomness"
		result.Confidence = 0.8
		return result
	}

	// Check for Base64-like patterns
	if h.looksLikeBase64(nameToCheck) {
		result.Triggered = true
		result.Score = 0.7
		result.Details = "Name appears to contain Base64 encoded data"
		return result
	}

	// Check for hex-like patterns
	if h.looksLikeHex(nameToCheck) {
		result.Triggered = true
		result.Score = 0.6
		result.Details = "Name appears to contain hexadecimal data"
		return result
	}

	return result
}

func (h *EntropyHeuristic) calculateEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	// Count character frequencies
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}

	// Calculate entropy
	var entropy float64
	length := float64(len(s))
	
	for _, count := range freq {
		if count > 0 {
			p := count / length
			entropy -= p * math.Log2(p)
		}
	}

	return entropy
}

func (h *EntropyHeuristic) isLegitimateNaming(name string) bool {
	// Common legitimate patterns
	patterns := []string{
		`^com\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+`,  // com.company.product
		`^org\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+`,  // org.organization.product
		`^io\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+`,   // io.company.product
		`^[a-zA-Z0-9]+-[a-zA-Z0-9]+$`,         // product-component
		`^[A-Z][a-zA-Z]+Agent$`,               // ProductAgent
		`^[A-Z][a-zA-Z]+Helper$`,              // ProductHelper
		`^[A-Z][a-zA-Z]+Daemon$`,              // ProductDaemon
	}

	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, name); matched {
			return true
		}
	}

	return false
}

func (h *EntropyHeuristic) isSuspiciousNaming(name string) bool {
	name = strings.ToLower(name)
	
	// Check for Apple mimicry
	appleMimicry := []string{
		"com.apple.",
		"com.aaple.",
		"com.appie.",
		"com.aple.",
		"systemd",
		"systemagent",
		"coreservices",
		"macos",
		"macosupdate",
	}

	for _, mimic := range appleMimicry {
		if strings.Contains(name, mimic) && !strings.HasPrefix(name, "com.apple.") {
			return true
		}
	}

	// Check for generic suspicious names
	suspicious := []string{
		"update",
		"updater",
		"service",
		"system",
		"helper",
		"agent",
		"daemon",
	}

	// Count how many suspicious words appear
	count := 0
	for _, word := range suspicious {
		if strings.Contains(name, word) {
			count++
		}
	}

	// Multiple generic words is suspicious
	return count >= 2
}

func (h *EntropyHeuristic) looksLikeBase64(s string) bool {
	// Remove common prefixes/suffixes
	s = strings.TrimPrefix(s, "com.")
	s = strings.TrimSuffix(s, ".plist")
	
	// Base64 pattern
	base64Pattern := `^[A-Za-z0-9+/]{20,}={0,2}$`
	matched, _ := regexp.MatchString(base64Pattern, s)
	return matched
}

func (h *EntropyHeuristic) looksLikeHex(s string) bool {
	// Remove common prefixes/suffixes
	s = strings.TrimPrefix(s, "com.")
	s = strings.TrimSuffix(s, ".plist")
	
	// Hex pattern (at least 16 characters)
	hexPattern := `^[0-9a-fA-F]{16,}$`
	matched, _ := regexp.MatchString(hexPattern, s)
	return matched
}