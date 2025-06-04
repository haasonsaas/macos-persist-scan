package collectors

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/haasonsaas/macos-persist-scan/pkg/scanner"
	"howett.net/plist"
)

type ConfigProfilesScanner struct{}

func NewConfigProfilesScanner() *ConfigProfilesScanner {
	return &ConfigProfilesScanner{}
}

func (s *ConfigProfilesScanner) Type() scanner.MechanismType {
	return scanner.MechanismConfigProfile
}

func (s *ConfigProfilesScanner) Scan() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Use system_profiler to get installed profiles
	profileItems, err := s.scanViaSystemProfiler()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning profiles via system_profiler: %v\n", err)
	} else {
		items = append(items, profileItems...)
	}

	// Also scan the profiles directory directly
	dirItems, err := s.scanProfilesDirectory()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning profiles directory: %v\n", err)
	} else {
		items = append(items, dirItems...)
	}

	return items, nil
}

type profileData struct {
	ProfileDisplayName  string                 `plist:"ProfileDisplayName"`
	ProfileIdentifier   string                 `plist:"ProfileIdentifier"`
	ProfileOrganization string                 `plist:"ProfileOrganization"`
	ProfileDescription  string                 `plist:"ProfileDescription"`
	ProfileInstallDate  time.Time             `plist:"ProfileInstallDate"`
	ProfileItems        []profilePayload      `plist:"ProfileItems"`
	PayloadContent      []map[string]interface{} `plist:"PayloadContent"`
}

type profilePayload struct {
	PayloadType        string                 `plist:"PayloadType"`
	PayloadIdentifier  string                 `plist:"PayloadIdentifier"`
	PayloadDisplayName string                 `plist:"PayloadDisplayName"`
	PayloadContent     map[string]interface{} `plist:"PayloadContent"`
}

func (s *ConfigProfilesScanner) scanViaSystemProfiler() ([]scanner.PersistenceItem, error) {
	// Run system_profiler to get configuration profiles
	cmd := exec.Command("system_profiler", "SPConfigurationProfileDataType", "-xml")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("running system_profiler: %w", err)
	}

	// Parse the plist output
	var spData []map[string]interface{}
	_, err = plist.Unmarshal(output, &spData)
	if err != nil {
		return nil, fmt.Errorf("parsing system_profiler output: %w", err)
	}

	var items []scanner.PersistenceItem

	// Process each profile section
	for _, section := range spData {
		profiles, ok := section["_items"].([]interface{})
		if !ok {
			continue
		}

		for _, profile := range profiles {
			profileMap, ok := profile.(map[string]interface{})
			if !ok {
				continue
			}

			item := s.parseProfileData(profileMap)
			if item != nil {
				items = append(items, *item)
			}
		}
	}

	return items, nil
}

func (s *ConfigProfilesScanner) parseProfileData(data map[string]interface{}) *scanner.PersistenceItem {
	name, _ := data["_name"].(string)
	if name == "" {
		name = "Unknown Profile"
	}

	identifier, _ := data["spconfigprofile_profile_identifier"].(string)
	organization, _ := data["spconfigprofile_organization"].(string)
	description, _ := data["spconfigprofile_description"].(string)
	
	// Check for potentially suspicious payload types
	suspiciousPayloads := s.checkForSuspiciousPayloads(data)

	item := &scanner.PersistenceItem{
		Mechanism:  scanner.MechanismConfigProfile,
		Label:      name,
		Path:       "Configuration Profile",
		ModifiedAt: time.Now(), // Can't get exact install time from this format
		RawData: map[string]interface{}{
			"description":        fmt.Sprintf("Profile: %s (ID: %s, Org: %s)", name, identifier, organization),
			"ProfileName":        name,
			"ProfileIdentifier":  identifier,
			"Organization":       organization,
			"Description":        description,
			"SuspiciousPayloads": suspiciousPayloads,
			"FullData":          data,
		},
	}

	// Try to determine if this profile contains persistence mechanisms
	if len(suspiciousPayloads) > 0 {
		item.RawData["HasPersistenceMechanisms"] = true
		item.RawData["description"] = fmt.Sprintf("%s - Contains persistence payloads: %s", 
			item.RawData["description"], strings.Join(suspiciousPayloads, ", "))
	}

	return item
}

func (s *ConfigProfilesScanner) checkForSuspiciousPayloads(profile map[string]interface{}) []string {
	var suspicious []string

	// Common persistence-related payload types to flag
	persistencePayloads := map[string]string{
		"com.apple.loginitems.managed": "Login Items",
		"com.apple.LaunchServices.managed": "Launch Services",
		"com.apple.systemextensions": "System Extensions",
		"com.apple.TCC.configuration-profile-policy": "Privacy Preferences",
		"com.apple.notificationsettings": "Notification Settings",
		"com.apple.servicemanagement": "Service Management",
		"com.apple.system.extension.network-extension": "Network Extension",
		"com.apple.system.extension.endpoint-security": "Endpoint Security Extension",
	}

	// Check payload content
	if payloadContent, ok := profile["_payloads"].([]interface{}); ok {
		for _, payload := range payloadContent {
			if payloadMap, ok := payload.(map[string]interface{}); ok {
				if payloadType, ok := payloadMap["PayloadType"].(string); ok {
					if desc, found := persistencePayloads[payloadType]; found {
						suspicious = append(suspicious, desc)
					}
				}
			}
		}
	}

	return suspicious
}

func (s *ConfigProfilesScanner) scanProfilesDirectory() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Common locations for configuration profiles
	profileDirs := []string{
		"/Library/Managed Preferences",
		"/Library/ConfigurationProfiles",
		"/var/db/ConfigurationProfiles/Store",
	}

	for _, dir := range profileDirs {
		dirItems, err := s.scanDirectory(dir)
		if err != nil {
			continue // Skip inaccessible directories
		}
		items = append(items, dirItems...)
	}

	return items, nil
}

func (s *ConfigProfilesScanner) scanDirectory(dir string) ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		// Look for plist files
		if strings.HasSuffix(entry.Name(), ".plist") || strings.HasSuffix(entry.Name(), ".mobileconfig") {
			path := filepath.Join(dir, entry.Name())
			
			data, err := os.ReadFile(path)
			if err != nil {
				continue
			}

			// Try to parse as plist
			var profileContent map[string]interface{}
			_, err = plist.Unmarshal(data, &profileContent)
			if err != nil {
				continue
			}

			info, _ := entry.Info()
			modTime := time.Now()
			if info != nil {
				modTime = info.ModTime()
			}

			item := scanner.PersistenceItem{
				Mechanism:  scanner.MechanismConfigProfile,
				Label:      entry.Name(),
				Path:       path,
				ModifiedAt: modTime,
				RawData:    profileContent,
			}
			item.RawData["description"] = fmt.Sprintf("Configuration profile: %s", entry.Name())
			item.RawData["content"] = string(data)

			// Extract profile name if available
			if name, ok := profileContent["PayloadDisplayName"].(string); ok && name != "" {
				item.Label = name
			}

			items = append(items, item)
		}
	}

	return items, nil
}