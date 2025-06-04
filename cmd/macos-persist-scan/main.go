package main

import (
	"context"
	"fmt"
	"os"

	"github.com/haasonsaas/macos-persist-scan/internal/collectors"
	"github.com/haasonsaas/macos-persist-scan/internal/heuristics"
	"github.com/haasonsaas/macos-persist-scan/pkg/output"
	"github.com/haasonsaas/macos-persist-scan/pkg/risk"
	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
	"github.com/spf13/cobra"
)

var (
	outputFormat string
	parallel     bool
	verbose      bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "macos-persist-scan",
		Short: "Scan macOS for persistence mechanisms",
		Long: `A security tool that discovers, analyzes, and reports on macOS persistence 
mechanisms to help identify potentially malicious software installations.`,
	}

	// Global flags
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")

	// Scan command
	scanCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan system for persistence mechanisms",
		Long:  `Perform a comprehensive scan of all macOS persistence mechanisms.`,
		RunE:  runScan,
	}
	
	scanCmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format (table, json, sarif)")
	scanCmd.Flags().BoolVarP(&parallel, "parallel", "p", true, "Run scanners in parallel")

	// Add commands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(versionCmd())

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Initialize scanners
	scanners := []scanner.Scanner{
		collectors.NewLaunchAgentScanner(),
		collectors.NewLaunchDaemonScanner(),
		collectors.NewLoginItemsScanner(),
		collectors.NewConfigProfilesScanner(),
		collectors.NewCronScanner(),
		collectors.NewPeriodicScanner(),
		collectors.NewLoginHooksScanner(),
	}

	// Initialize heuristics
	heuristicsList := []risk.Heuristic{
		heuristics.NewSignatureHeuristic(),
		heuristics.NewPathHeuristic(),
		heuristics.NewBehaviorHeuristic(),
		heuristics.NewEntropyHeuristic(),
	}

	// Create risk engine
	riskEngine := risk.NewEngine(heuristicsList)

	// Create orchestrator
	orchestrator := scanner.NewOrchestrator(scanners, parallel)

	// Run scan
	if verbose {
		fmt.Println("Starting scan...")
	}

	result, err := orchestrator.RunScan(ctx)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Assess risk for each item
	for i := range result.Items {
		result.Items[i].Risk = riskEngine.AssessRisk(&result.Items[i])
	}

	// Format output
	formatter := output.GetFormatter(output.FormatterType(outputFormat))
	if jsonFormatter, ok := formatter.(*output.JSONFormatter); ok && outputFormat == "json" {
		jsonFormatter.Pretty = true
	}

	outputData, err := formatter.Format(result)
	if err != nil {
		return fmt.Errorf("failed to format output: %w", err)
	}

	// Write output
	fmt.Print(string(outputData))

	// Set exit code based on findings
	if result.RiskSummary[scanner.RiskCritical] > 0 {
		os.Exit(3)
	} else if result.RiskSummary[scanner.RiskHigh] > 0 {
		os.Exit(2)
	} else if result.RiskSummary[scanner.RiskMedium] > 0 {
		os.Exit(1)
	}

	return nil
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("macos-persist-scan version 1.0.0")
		},
	}
}