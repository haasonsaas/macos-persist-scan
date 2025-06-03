package scanner

import (
	"time"
)

type MechanismType string

const (
	MechanismLaunchAgent     MechanismType = "LaunchAgent"
	MechanismLaunchDaemon    MechanismType = "LaunchDaemon"
	MechanismLoginItem       MechanismType = "LoginItem"
	MechanismConfigProfile   MechanismType = "ConfigurationProfile"
	MechanismCronJob         MechanismType = "CronJob"
	MechanismPeriodicScript  MechanismType = "PeriodicScript"
	MechanismLoginHook       MechanismType = "LoginHook"
	MechanismLogoutHook      MechanismType = "LogoutHook"
)

type RiskLevel string

const (
	RiskInfo     RiskLevel = "Info"
	RiskLow      RiskLevel = "Low"
	RiskMedium   RiskLevel = "Medium"
	RiskHigh     RiskLevel = "High"
	RiskCritical RiskLevel = "Critical"
)

type PersistenceItem struct {
	ID            string                 `json:"id"`
	Mechanism     MechanismType          `json:"mechanism"`
	Label         string                 `json:"label"`
	Path          string                 `json:"path"`
	Program       string                 `json:"program"`
	ProgramArgs   []string               `json:"program_args,omitempty"`
	User          string                 `json:"user,omitempty"`
	RunAtLoad     bool                   `json:"run_at_load"`
	KeepAlive     bool                   `json:"keep_alive"`
	Disabled      bool                   `json:"disabled"`
	CreatedAt     time.Time              `json:"created_at"`
	ModifiedAt    time.Time              `json:"modified_at"`
	FileMode      string                 `json:"file_mode"`
	Risk          RiskAssessment         `json:"risk"`
	RawData       map[string]interface{} `json:"raw_data,omitempty"`
	Errors        []string               `json:"errors,omitempty"`
}

type RiskAssessment struct {
	Level       RiskLevel              `json:"level"`
	Score       float64                `json:"score"`
	Confidence  float64                `json:"confidence"`
	Reasons     []string               `json:"reasons"`
	Heuristics  []HeuristicResult      `json:"heuristics"`
}

type HeuristicResult struct {
	Name        string    `json:"name"`
	Triggered   bool      `json:"triggered"`
	Score       float64   `json:"score"`
	Confidence  float64   `json:"confidence"`
	Details     string    `json:"details"`
}

type ScanResult struct {
	StartTime       time.Time         `json:"start_time"`
	EndTime         time.Time         `json:"end_time"`
	Duration        time.Duration     `json:"duration"`
	Items           []PersistenceItem `json:"items"`
	TotalItems      int               `json:"total_items"`
	RiskSummary     map[RiskLevel]int `json:"risk_summary"`
	Errors          []ScanError       `json:"errors,omitempty"`
	PermissionIssues []string         `json:"permission_issues,omitempty"`
}

type ScanError struct {
	Mechanism   MechanismType `json:"mechanism"`
	Path        string        `json:"path,omitempty"`
	Error       string        `json:"error"`
	Timestamp   time.Time     `json:"timestamp"`
}

type Scanner interface {
	Scan() ([]PersistenceItem, error)
	Type() MechanismType
}