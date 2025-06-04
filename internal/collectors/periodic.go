package collectors

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type PeriodicScanner struct{}

func NewPeriodicScanner() *PeriodicScanner {
	return &PeriodicScanner{}
}

func (s *PeriodicScanner) Type() scanner.MechanismType {
	return scanner.MechanismPeriodicScript
}

func (s *PeriodicScanner) Scan() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Scan standard periodic directories
	periods := []string{"daily", "weekly", "monthly"}
	
	for _, period := range periods {
		periodItems, err := s.scanPeriodDirectory(period)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: scanning %s periodic scripts: %v\n", period, err)
		} else {
			items = append(items, periodItems...)
		}
	}

	// Check periodic.conf for custom configurations
	confItems, err := s.scanPeriodicConf()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning periodic.conf: %v\n", err)
	} else {
		items = append(items, confItems...)
	}

	// Check for custom periodic directories
	customItems, err := s.scanCustomDirectories()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning custom periodic directories: %v\n", err)
	} else {
		items = append(items, customItems...)
	}

	return items, nil
}

func (s *PeriodicScanner) scanPeriodDirectory(period string) ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	baseDir := fmt.Sprintf("/etc/periodic/%s", period)
	
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return items, nil // Directory doesn't exist
		}
		return nil, fmt.Errorf("reading directory %s: %w", baseDir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Skip backup files and non-executable files
		name := entry.Name()
		if strings.HasSuffix(name, "~") || strings.HasPrefix(name, ".") {
			continue
		}

		path := filepath.Join(baseDir, name)
		
		// Check if file is executable
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		// Read the script content
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Analyze the script
		scriptInfo := s.analyzeScript(string(data))

		item := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismPeriodicScript,
			Label:      fmt.Sprintf("%s: %s", strings.Title(period), name),
			Path:       path,
			ModifiedAt: info.ModTime(),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("Periodic %s script: %s", period, name),
				"period":      period,
				"script":      name,
				"executable":  info.Mode()&0111 != 0,
				"permissions": fmt.Sprintf("%04o", info.Mode().Perm()),
				"scriptInfo":  scriptInfo,
				"content":     string(data),
			},
		}
		if interpreterVal, ok := scriptInfo["interpreter"].(string); ok {
			item.Program = interpreterVal
		}

		items = append(items, item)
	}

	return items, nil
}

func (s *PeriodicScanner) scanPeriodicConf() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	confPaths := []string{
		"/etc/periodic.conf",
		"/etc/defaults/periodic.conf",
		"/etc/periodic.conf.local",
	}

	for _, confPath := range confPaths {
		data, err := os.ReadFile(confPath)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			continue
		}

		// Parse configuration
		config := s.parsePeriodicConf(string(data))
		
		if len(config) > 0 {
			item := scanner.PersistenceItem{
				Mechanism:  scanner.MechanismPeriodicScript,
				Label:      fmt.Sprintf("Periodic Configuration: %s", filepath.Base(confPath)),
				Path:       confPath,
				ModifiedAt: getFileModTime(confPath),
				RawData: map[string]interface{}{
					"description": fmt.Sprintf("Periodic configuration file with %d settings", len(config)),
					"settings": config,
					"file":     filepath.Base(confPath),
					"content":  string(data),
				},
			}

			// Check for custom script paths
			customPaths := s.extractCustomPaths(config)
			if len(customPaths) > 0 {
				item.RawData["customPaths"] = customPaths
				item.RawData["description"] = item.RawData["description"].(string) + fmt.Sprintf(" (includes %d custom paths)", len(customPaths))
			}

			items = append(items, item)
		}
	}

	return items, nil
}

func (s *PeriodicScanner) scanCustomDirectories() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Common custom locations
	customDirs := []string{
		"/usr/local/etc/periodic",
		"/opt/local/etc/periodic",
	}

	for _, baseDir := range customDirs {
		// Check for daily/weekly/monthly subdirectories
		periods := []string{"daily", "weekly", "monthly"}
		
		for _, period := range periods {
			dir := filepath.Join(baseDir, period)
			
			entries, err := os.ReadDir(dir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				path := filepath.Join(dir, entry.Name())
				
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}

				info, _ := entry.Info()
				modTime := time.Now()
				if info != nil {
					modTime = info.ModTime()
				}

				scriptInfo := s.analyzeScript(string(data))

				item := scanner.PersistenceItem{
					Mechanism:  scanner.MechanismPeriodicScript,
					Label:      fmt.Sprintf("Custom %s: %s", strings.Title(period), entry.Name()),
					Path:       path,
					ModifiedAt: modTime,
					RawData: map[string]interface{}{
						"description": fmt.Sprintf("Custom periodic %s script: %s in %s", period, entry.Name(), baseDir),
						"period":      period,
						"script":      entry.Name(),
						"custom":      true,
						"baseDir":     baseDir,
						"scriptInfo":  scriptInfo,
						"content":     string(data),
					},
				}
				if interpreterVal, ok := scriptInfo["interpreter"].(string); ok {
					item.Program = interpreterVal
				}

				items = append(items, item)
			}
		}
	}

	return items, nil
}

func (s *PeriodicScanner) parsePeriodicConf(content string) map[string]string {
	config := make(map[string]string)

	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		
		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse shell variable assignments
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				
				// Remove quotes
				value = strings.Trim(value, "\"'")
				
				config[key] = value
			}
		}
	}

	return config
}

func (s *PeriodicScanner) extractCustomPaths(config map[string]string) []string {
	var paths []string
	
	// Look for variables that might contain custom script paths
	pathVars := []string{
		"local_periodic",
		"daily_local",
		"weekly_local",
		"monthly_local",
	}

	for _, varName := range pathVars {
		if value, ok := config[varName]; ok && value != "" {
			// Split on spaces or colons
			parts := strings.FieldsFunc(value, func(r rune) bool {
				return r == ' ' || r == ':'
			})
			paths = append(paths, parts...)
		}
	}

	// Also check for any variable ending with _dir or _path
	for key, value := range config {
		if strings.HasSuffix(key, "_dir") || strings.HasSuffix(key, "_path") {
			if value != "" && strings.HasPrefix(value, "/") {
				paths = append(paths, value)
			}
		}
	}

	return paths
}

func (s *PeriodicScanner) analyzeScript(content string) map[string]interface{} {
	info := make(map[string]interface{})

	// Extract shebang
	lines := strings.Split(content, "\n")
	if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
		shebang := strings.TrimPrefix(lines[0], "#!")
		parts := strings.Fields(shebang)
		if len(parts) > 0 {
			info["interpreter"] = parts[0]
		}
	}

	// Count lines
	info["lineCount"] = len(lines)

	// Look for suspicious patterns
	suspiciousPatterns := []string{
		"curl",
		"wget",
		"nc ",
		"netcat",
		"base64",
		"eval",
		"python -c",
		"perl -e",
		"ruby -e",
		"/dev/tcp",
		"mkfifo",
	}

	var foundPatterns []string
	contentLower := strings.ToLower(content)
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(contentLower, pattern) {
			foundPatterns = append(foundPatterns, pattern)
		}
	}

	if len(foundPatterns) > 0 {
		info["suspiciousPatterns"] = foundPatterns
	}

	// Check if script appears to be from a package manager
	if strings.Contains(content, "MacPorts") || strings.Contains(content, "Homebrew") {
		info["packageManager"] = true
	}

	return info
}