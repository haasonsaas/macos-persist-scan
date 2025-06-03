package collectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
	"howett.net/plist"
)

type LaunchdScanner struct {
	paths        []string
	mechanismType scanner.MechanismType
}

type LaunchdPlist struct {
	Label              string                 `plist:"Label"`
	Program            string                 `plist:"Program"`
	ProgramArguments   []string               `plist:"ProgramArguments"`
	RunAtLoad          bool                   `plist:"RunAtLoad"`
	KeepAlive          interface{}            `plist:"KeepAlive"`
	Disabled           bool                   `plist:"Disabled"`
	UserName           string                 `plist:"UserName"`
	GroupName          string                 `plist:"GroupName"`
	StartInterval      int                    `plist:"StartInterval"`
	StartCalendarInterval interface{}         `plist:"StartCalendarInterval"`
	WatchPaths         []string               `plist:"WatchPaths"`
	QueueDirectories   []string               `plist:"QueueDirectories"`
	StandardInPath     string                 `plist:"StandardInPath"`
	StandardOutPath    string                 `plist:"StandardOutPath"`
	StandardErrorPath  string                 `plist:"StandardErrorPath"`
}

func NewLaunchAgentScanner() *LaunchdScanner {
	return &LaunchdScanner{
		paths: []string{
			"/Library/LaunchAgents",
			"/System/Library/LaunchAgents",
			filepath.Join(os.Getenv("HOME"), "Library/LaunchAgents"),
		},
		mechanismType: scanner.MechanismLaunchAgent,
	}
}

func NewLaunchDaemonScanner() *LaunchdScanner {
	return &LaunchdScanner{
		paths: []string{
			"/Library/LaunchDaemons",
			"/System/Library/LaunchDaemons",
		},
		mechanismType: scanner.MechanismLaunchDaemon,
	}
}

func (s *LaunchdScanner) Type() scanner.MechanismType {
	return s.mechanismType
}

func (s *LaunchdScanner) Scan() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem
	
	for _, basePath := range s.paths {
		if _, err := os.Stat(basePath); os.IsNotExist(err) {
			continue
		}
		
		err := filepath.Walk(basePath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				// Log permission errors but continue
				if os.IsPermission(err) {
					return nil
				}
				return nil
			}
			
			if strings.HasSuffix(path, ".plist") && !info.IsDir() {
				item, err := s.parsePlist(path, info)
				if err == nil && item != nil {
					items = append(items, *item)
				}
			}
			return nil
		})
		
		if err != nil && !os.IsPermission(err) {
			return items, fmt.Errorf("error walking %s: %w", basePath, err)
		}
	}
	
	return items, nil
}

func (s *LaunchdScanner) parsePlist(path string, info os.FileInfo) (*scanner.PersistenceItem, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var launchdPlist LaunchdPlist
	decoder := plist.NewDecoder(file)
	if err := decoder.Decode(&launchdPlist); err != nil {
		return nil, fmt.Errorf("error decoding plist %s: %w", path, err)
	}
	
	// Extract program path
	program := launchdPlist.Program
	if program == "" && len(launchdPlist.ProgramArguments) > 0 {
		program = launchdPlist.ProgramArguments[0]
	}
	
	// Determine if KeepAlive is set
	keepAlive := false
	switch v := launchdPlist.KeepAlive.(type) {
	case bool:
		keepAlive = v
	case map[string]interface{}:
		keepAlive = len(v) > 0
	}
	
	item := &scanner.PersistenceItem{
		ID:          filepath.Base(path),
		Mechanism:   s.mechanismType,
		Label:       launchdPlist.Label,
		Path:        path,
		Program:     program,
		ProgramArgs: launchdPlist.ProgramArguments,
		User:        launchdPlist.UserName,
		RunAtLoad:   launchdPlist.RunAtLoad,
		KeepAlive:   keepAlive,
		Disabled:    launchdPlist.Disabled,
		ModifiedAt:  info.ModTime(),
		FileMode:    info.Mode().String(),
		RawData:     make(map[string]interface{}),
	}
	
	// Store relevant raw data
	if launchdPlist.StartInterval > 0 {
		item.RawData["StartInterval"] = launchdPlist.StartInterval
	}
	if launchdPlist.StartCalendarInterval != nil {
		item.RawData["StartCalendarInterval"] = launchdPlist.StartCalendarInterval
	}
	if len(launchdPlist.WatchPaths) > 0 {
		item.RawData["WatchPaths"] = launchdPlist.WatchPaths
	}
	if len(launchdPlist.QueueDirectories) > 0 {
		item.RawData["QueueDirectories"] = launchdPlist.QueueDirectories
	}
	
	return item, nil
}