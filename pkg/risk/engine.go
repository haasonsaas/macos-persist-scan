package risk

import (
	"math"
	"sort"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type Engine struct {
	heuristics []Heuristic
}

type Heuristic interface {
	Analyze(item *scanner.PersistenceItem) scanner.HeuristicResult
	Name() string
}

func NewEngine(heuristics []Heuristic) *Engine {
	return &Engine{
		heuristics: heuristics,
	}
}

func (e *Engine) AssessRisk(item *scanner.PersistenceItem) scanner.RiskAssessment {
	assessment := scanner.RiskAssessment{
		Level:      scanner.RiskInfo,
		Score:      0.0,
		Confidence: 1.0,
		Reasons:    []string{},
		Heuristics: []scanner.HeuristicResult{},
	}

	var totalScore float64
	var totalConfidence float64
	var triggeredCount int

	// Run all heuristics
	for _, h := range e.heuristics {
		result := h.Analyze(item)
		assessment.Heuristics = append(assessment.Heuristics, result)
		
		if result.Triggered {
			triggeredCount++
			totalScore += result.Score * result.Confidence
			totalConfidence += result.Confidence
			assessment.Reasons = append(assessment.Reasons, result.Details)
		}
	}

	// Calculate weighted average score
	if triggeredCount > 0 {
		assessment.Score = totalScore / totalConfidence
		assessment.Confidence = math.Min(totalConfidence/float64(triggeredCount), 1.0)
	}

	// Determine risk level based on score
	assessment.Level = e.scoreToRiskLevel(assessment.Score)

	// Sort heuristics by score (highest first)
	sort.Slice(assessment.Heuristics, func(i, j int) bool {
		return assessment.Heuristics[i].Score > assessment.Heuristics[j].Score
	})

	return assessment
}

func (e *Engine) scoreToRiskLevel(score float64) scanner.RiskLevel {
	switch {
	case score >= 0.8:
		return scanner.RiskCritical
	case score >= 0.6:
		return scanner.RiskHigh
	case score >= 0.4:
		return scanner.RiskMedium
	case score >= 0.2:
		return scanner.RiskLow
	default:
		return scanner.RiskInfo
	}
}

func (e *Engine) AddHeuristic(h Heuristic) {
	e.heuristics = append(e.heuristics, h)
}

func (e *Engine) GetHeuristics() []Heuristic {
	return e.heuristics
}