package output

import (
	"encoding/json"
	"fmt"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type SARIFFormatter struct{}

type SARIF struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool    SARIFTool     `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	InformationURI  string      `json:"informationUri"`
	Rules           []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	ShortDescription SARIFDescription  `json:"shortDescription"`
	FullDescription  SARIFDescription  `json:"fullDescription"`
	DefaultLevel     string            `json:"defaultConfiguration"`
}

type SARIFDescription struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   SARIFMessage     `json:"message"`
	Locations []SARIFLocation  `json:"locations"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation `json:"physicalLocation"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

func (f *SARIFFormatter) Format(result *scanner.ScanResult) ([]byte, error) {
	sarif := SARIF{
		Version: "2.1.0",
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Runs: []SARIFRun{{
			Tool: SARIFTool{
				Driver: SARIFDriver{
					Name:           "macos-persist-scan",
					Version:        "1.0.0",
					InformationURI: "https://github.com/haasonsaas/macos-persist-scan",
					Rules:          f.generateRules(),
				},
			},
			Results: f.convertResults(result.Items),
		}},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

func (f *SARIFFormatter) generateRules() []SARIFRule {
	return []SARIFRule{
		{
			ID:   "unsigned-binary",
			Name: "Unsigned Binary",
			ShortDescription: SARIFDescription{
				Text: "Binary is not code signed",
			},
			FullDescription: SARIFDescription{
				Text: "The persistence mechanism uses an unsigned binary, which could indicate malicious software",
			},
			DefaultLevel: "warning",
		},
		{
			ID:   "suspicious-path",
			Name: "Suspicious File Path",
			ShortDescription: SARIFDescription{
				Text: "Binary located in suspicious directory",
			},
			FullDescription: SARIFDescription{
				Text: "The persistence mechanism references a binary in a temporary or unusual location",
			},
			DefaultLevel: "warning",
		},
		{
			ID:   "suspicious-behavior",
			Name: "Suspicious Behavior Pattern",
			ShortDescription: SARIFDescription{
				Text: "Persistence exhibits suspicious behavioral patterns",
			},
			FullDescription: SARIFDescription{
				Text: "The persistence mechanism shows patterns commonly associated with malware",
			},
			DefaultLevel: "warning",
		},
		{
			ID:   "high-entropy-name",
			Name: "High Entropy Name",
			ShortDescription: SARIFDescription{
				Text: "Name appears random or obfuscated",
			},
			FullDescription: SARIFDescription{
				Text: "The persistence item has a name with high entropy, suggesting randomness or obfuscation",
			},
			DefaultLevel: "note",
		},
	}
}

func (f *SARIFFormatter) convertResults(items []scanner.PersistenceItem) []SARIFResult {
	var results []SARIFResult
	
	for _, item := range items {
		if item.Risk.Level == scanner.RiskInfo {
			continue // Skip info level items in SARIF
		}
		
		// Map heuristics to rules
		for _, heuristic := range item.Risk.Heuristics {
			if !heuristic.Triggered {
				continue
			}
			
			ruleID := f.heuristicToRuleID(heuristic.Name)
			if ruleID == "" {
				continue
			}
			
			result := SARIFResult{
				RuleID: ruleID,
				Level:  f.riskLevelToSARIF(item.Risk.Level),
				Message: SARIFMessage{
					Text: fmt.Sprintf("%s: %s", item.Label, heuristic.Details),
				},
				Locations: []SARIFLocation{{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: item.Path,
						},
					},
				}},
			}
			
			results = append(results, result)
		}
	}
	
	return results
}

func (f *SARIFFormatter) heuristicToRuleID(heuristicName string) string {
	mapping := map[string]string{
		"signature_verification": "unsigned-binary",
		"suspicious_path":        "suspicious-path",
		"suspicious_behavior":    "suspicious-behavior",
		"name_entropy":          "high-entropy-name",
	}
	
	return mapping[heuristicName]
}

func (f *SARIFFormatter) riskLevelToSARIF(level scanner.RiskLevel) string {
	switch level {
	case scanner.RiskCritical, scanner.RiskHigh:
		return "error"
	case scanner.RiskMedium:
		return "warning"
	case scanner.RiskLow:
		return "note"
	default:
		return "none"
	}
}