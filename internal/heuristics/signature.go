package heuristics

import (
	"os/exec"
	"strings"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type SignatureHeuristic struct{}

func NewSignatureHeuristic() *SignatureHeuristic {
	return &SignatureHeuristic{}
}

func (h *SignatureHeuristic) Name() string {
	return "signature_verification"
}

func (h *SignatureHeuristic) Analyze(item *scanner.PersistenceItem) scanner.HeuristicResult {
	result := scanner.HeuristicResult{
		Name:       h.Name(),
		Triggered:  false,
		Score:      0.0,
		Confidence: 0.8,
		Details:    "",
	}

	if item.Program == "" {
		return result
	}

	// Check code signature using codesign
	cmd := exec.Command("codesign", "-dv", "--verbose=4", item.Program)
	output, err := cmd.CombinedOutput()
	
	if err != nil {
		// Binary is unsigned or invalid signature
		result.Triggered = true
		result.Score = 0.7
		result.Details = "Binary is unsigned or has invalid signature"
		
		if strings.Contains(string(output), "code object is not signed") {
			result.Details = "Binary is not code signed"
			result.Score = 0.6
		} else if strings.Contains(string(output), "adhoc") {
			result.Details = "Binary has ad-hoc signature (not from trusted developer)"
			result.Score = 0.8
		}
		return result
	}

	outputStr := string(output)
	
	// Check for Apple signature
	if strings.Contains(outputStr, "Authority=Apple") || 
	   strings.Contains(outputStr, "com.apple.") {
		// Apple-signed binaries are generally trusted
		result.Triggered = false
		return result
	}

	// Check for Developer ID
	if strings.Contains(outputStr, "Authority=Developer ID") {
		result.Triggered = true
		result.Score = 0.2
		result.Details = "Binary signed with Developer ID certificate"
		result.Confidence = 0.9
		return result
	}

	// Check for revoked certificates
	if strings.Contains(outputStr, "REVOKED") {
		result.Triggered = true
		result.Score = 0.9
		result.Details = "Binary signed with revoked certificate"
		result.Confidence = 1.0
		return result
	}

	// Unknown signature
	result.Triggered = true
	result.Score = 0.5
	result.Details = "Binary has unknown signature type"
	
	return result
}