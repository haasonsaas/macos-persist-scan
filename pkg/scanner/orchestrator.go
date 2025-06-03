package scanner

import (
	"context"
	"sync"
	"time"
)

type Orchestrator struct {
	scanners []Scanner
	parallel bool
}

func NewOrchestrator(scanners []Scanner, parallel bool) *Orchestrator {
	return &Orchestrator{
		scanners: scanners,
		parallel: parallel,
	}
}

func (o *Orchestrator) RunScan(ctx context.Context) (*ScanResult, error) {
	result := &ScanResult{
		StartTime:   time.Now(),
		RiskSummary: make(map[RiskLevel]int),
	}

	var allItems []PersistenceItem
	var allErrors []ScanError
	var mu sync.Mutex

	if o.parallel {
		var wg sync.WaitGroup
		for _, scanner := range o.scanners {
			wg.Add(1)
			go func(s Scanner) {
				defer wg.Done()
				
				items, err := s.Scan()
				mu.Lock()
				defer mu.Unlock()
				
				if err != nil {
					allErrors = append(allErrors, ScanError{
						Mechanism: s.Type(),
						Error:     err.Error(),
						Timestamp: time.Now(),
					})
				} else {
					allItems = append(allItems, items...)
				}
			}(scanner)
		}
		wg.Wait()
	} else {
		for _, scanner := range o.scanners {
			items, err := scanner.Scan()
			if err != nil {
				allErrors = append(allErrors, ScanError{
					Mechanism: scanner.Type(),
					Error:     err.Error(),
					Timestamp: time.Now(),
				})
			} else {
				allItems = append(allItems, items...)
			}
		}
	}

	// Calculate risk summary
	for _, item := range allItems {
		result.RiskSummary[item.Risk.Level]++
	}

	result.Items = allItems
	result.TotalItems = len(allItems)
	result.Errors = allErrors
	result.EndTime = time.Now()
	result.Duration = result.EndTime.Sub(result.StartTime)

	return result, nil
}

func (o *Orchestrator) AddScanner(scanner Scanner) {
	o.scanners = append(o.scanners, scanner)
}

func (o *Orchestrator) GetScanners() []Scanner {
	return o.scanners
}