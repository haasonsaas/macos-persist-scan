package collectors

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
)

type CronScanner struct{}

func NewCronScanner() *CronScanner {
	return &CronScanner{}
}

func (s *CronScanner) Type() scanner.MechanismType {
	return scanner.MechanismCronJob
}

func (s *CronScanner) Scan() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Scan system crontab
	systemItems, err := s.scanSystemCrontab()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning system crontab: %v\n", err)
	} else {
		items = append(items, systemItems...)
	}

	// Scan user crontabs
	userItems, err := s.scanUserCrontabs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning user crontabs: %v\n", err)
	} else {
		items = append(items, userItems...)
	}

	// Scan cron.d directory
	cronDItems, err := s.scanCronD()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning cron.d: %v\n", err)
	} else {
		items = append(items, cronDItems...)
	}

	return items, nil
}

func (s *CronScanner) scanSystemCrontab() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	crontabPath := "/etc/crontab"
	
	data, err := os.ReadFile(crontabPath)
	if err != nil {
		if os.IsNotExist(err) {
			return items, nil // No system crontab
		}
		return nil, fmt.Errorf("reading system crontab: %w", err)
	}

	entries := s.parseCrontab(string(data), "root")
	
	if len(entries) > 0 {
		item := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismCronJob,
			Label:      "System Crontab",
			Path:       crontabPath,
			User:       "root",
			ModifiedAt: getFileModTime(crontabPath),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("System crontab with %d entries", len(entries)),
				"entries": entries,
				"user":    "root",
				"content": string(data),
			},
		}
		items = append(items, item)
	}

	return items, nil
}

func (s *CronScanner) scanUserCrontabs() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Check common locations for user crontabs
	crontabDirs := []string{
		"/usr/lib/cron/tabs",
		"/var/cron/tabs",
		"/var/spool/cron/crontabs",
	}

	for _, dir := range crontabDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue // Directory doesn't exist or no permission
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			username := entry.Name()
			path := filepath.Join(dir, username)
			
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			cronEntries := s.parseCrontab(string(data), username)
			
			if len(cronEntries) > 0 {
				info, _ := entry.Info()
				modTime := time.Now()
				if info != nil {
					modTime = info.ModTime()
				}

				item := scanner.PersistenceItem{
					Mechanism:  scanner.MechanismCronJob,
					Label:      fmt.Sprintf("User Crontab: %s", username),
					Path:       path,
					User:       username,
					ModifiedAt: modTime,
					RawData: map[string]interface{}{
						"description": fmt.Sprintf("Crontab for user %s with %d entries", username, len(cronEntries)),
						"entries": cronEntries,
						"user":    username,
						"content": string(data),
					},
				}
				items = append(items, item)
			}
		}
	}

	// Also check current user's crontab via crontab command
	currentUserItems, err := s.scanCurrentUserCrontab()
	if err == nil {
		items = append(items, currentUserItems...)
	}

	return items, nil
}

func (s *CronScanner) scanCurrentUserCrontab() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Get current user's crontab
	cmd := exec.Command("crontab", "-l")
	output, err := cmd.Output()
	if err != nil {
		// No crontab or error
		return items, nil
	}

	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = "current"
	}

	entries := s.parseCrontab(string(output), currentUser)
	
	if len(entries) > 0 {
		item := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismCronJob,
			Label:      fmt.Sprintf("User Crontab: %s", currentUser),
			Path:       "crontab -l",
			User:       currentUser,
			ModifiedAt: time.Now(),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("Active crontab for user %s with %d entries", currentUser, len(entries)),
				"entries": entries,
				"user":    currentUser,
				"content": string(output),
			},
		}
		items = append(items, item)
	}

	return items, nil
}

func (s *CronScanner) scanCronD() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Check /etc/cron.d directory
	cronDDir := "/etc/cron.d"
	
	entries, err := os.ReadDir(cronDDir)
	if err != nil {
		if os.IsNotExist(err) {
			return items, nil
		}
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}

		path := filepath.Join(cronDDir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Parse the cron file
		cronEntries := s.parseCronDFile(string(data))
		
		if len(cronEntries) > 0 {
			info, _ := entry.Info()
			modTime := time.Now()
			if info != nil {
				modTime = info.ModTime()
			}

			item := scanner.PersistenceItem{
				Mechanism:  scanner.MechanismCronJob,
				Label:      fmt.Sprintf("Cron.d: %s", entry.Name()),
				Path:       path,
				ModifiedAt: modTime,
				RawData: map[string]interface{}{
					"description": fmt.Sprintf("Cron configuration %s with %d entries", entry.Name(), len(cronEntries)),
					"entries": cronEntries,
					"file":    entry.Name(),
					"content": string(data),
				},
			}
			items = append(items, item)
		}
	}

	return items, nil
}

type cronEntry struct {
	Schedule    string `json:"schedule"`
	Command     string `json:"command"`
	User        string `json:"user,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
}

func (s *CronScanner) parseCrontab(content, defaultUser string) []cronEntry {
	var entries []cronEntry
	env := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Handle environment variables
		if strings.Contains(line, "=") && !strings.HasPrefix(line, "@") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				env[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
			continue
		}

		// Parse cron entry
		entry := s.parseCronLine(line, defaultUser)
		if entry != nil {
			// Copy current environment to entry
			if len(env) > 0 {
				entry.Environment = make(map[string]string)
				for k, v := range env {
					entry.Environment[k] = v
				}
			}
			entries = append(entries, *entry)
		}
	}

	return entries
}

func (s *CronScanner) parseCronDFile(content string) []cronEntry {
	var entries []cronEntry
	
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// cron.d files include username field
		entry := s.parseCronDLine(line)
		if entry != nil {
			entries = append(entries, *entry)
		}
	}

	return entries
}

func (s *CronScanner) parseCronLine(line, user string) *cronEntry {
	// Handle special schedule strings
	if strings.HasPrefix(line, "@") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return &cronEntry{
				Schedule: parts[0],
				Command:  strings.Join(parts[1:], " "),
				User:     user,
			}
		}
		return nil
	}

	// Standard cron format: minute hour day month weekday command
	fields := strings.Fields(line)
	if len(fields) >= 6 {
		return &cronEntry{
			Schedule: strings.Join(fields[0:5], " "),
			Command:  strings.Join(fields[5:], " "),
			User:     user,
		}
	}

	return nil
}

func (s *CronScanner) parseCronDLine(line string) *cronEntry {
	// cron.d format includes user: minute hour day month weekday user command
	fields := strings.Fields(line)
	
	// Handle special schedule strings
	if strings.HasPrefix(line, "@") && len(fields) >= 3 {
		return &cronEntry{
			Schedule: fields[0],
			User:     fields[1],
			Command:  strings.Join(fields[2:], " "),
		}
	}

	// Standard format with user field
	if len(fields) >= 7 {
		return &cronEntry{
			Schedule: strings.Join(fields[0:5], " "),
			User:     fields[5],
			Command:  strings.Join(fields[6:], " "),
		}
	}

	return nil
}