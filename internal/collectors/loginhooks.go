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

type LoginHooksScanner struct{}

func NewLoginHooksScanner() *LoginHooksScanner {
	return &LoginHooksScanner{}
}

func (s *LoginHooksScanner) Type() scanner.MechanismType {
	return scanner.MechanismLoginHook
}

func (s *LoginHooksScanner) Scan() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Scan system login window preferences
	systemItems, err := s.scanSystemLoginWindow()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning system login window: %v\n", err)
	} else {
		items = append(items, systemItems...)
	}

	// Scan user login window preferences
	userItems, err := s.scanUserLoginWindow()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning user login window: %v\n", err)
	} else {
		items = append(items, userItems...)
	}

	// Check for MDM-deployed hooks
	mdmItems, err := s.scanMDMHooks()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning MDM hooks: %v\n", err)
	} else {
		items = append(items, mdmItems...)
	}

	// Check defaults command for login/logout hooks
	defaultsItems, err := s.scanViaDefaults()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: scanning via defaults: %v\n", err)
	} else {
		items = append(items, defaultsItems...)
	}

	return items, nil
}

type loginWindowPrefs struct {
	LoginHook  string `plist:"LoginHook"`
	LogoutHook string `plist:"LogoutHook"`
}

func (s *LoginHooksScanner) scanSystemLoginWindow() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// System login window preferences
	systemPrefPath := "/Library/Preferences/com.apple.loginwindow.plist"
	
	data, err := os.ReadFile(systemPrefPath)
	if err != nil {
		if os.IsNotExist(err) {
			return items, nil
		}
		return nil, fmt.Errorf("reading system login window preferences: %w", err)
	}

	var prefs loginWindowPrefs
	_, err = plist.Unmarshal(data, &prefs)
	if err != nil {
		// Try as a generic map
		var genericPrefs map[string]interface{}
		_, err = plist.Unmarshal(data, &genericPrefs)
		if err != nil {
			return nil, fmt.Errorf("parsing login window preferences: %w", err)
		}
		
		// Extract hooks from generic map
		if loginHook, ok := genericPrefs["LoginHook"].(string); ok && loginHook != "" {
			prefs.LoginHook = loginHook
		}
		if logoutHook, ok := genericPrefs["LogoutHook"].(string); ok && logoutHook != "" {
			prefs.LogoutHook = logoutHook
		}
	}

	// Check for login hook
	if prefs.LoginHook != "" {
		item := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismLoginHook,
			Label:      "System Login Hook",
			Path:       systemPrefPath,
			Program:    prefs.LoginHook,
			ModifiedAt: getFileModTime(systemPrefPath),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("System-wide login hook: %s", prefs.LoginHook),
				"hook":        "login",
				"scope":       "system",
				"script":      prefs.LoginHook,
				"content":     string(data),
			},
		}
		
		// Read the hook script if it exists
		if scriptData, err := os.ReadFile(prefs.LoginHook); err == nil {
			item.RawData["scriptContent"] = string(scriptData)
		}
		
		items = append(items, item)
	}

	// Check for logout hook
	if prefs.LogoutHook != "" {
		item := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismLogoutHook,
			Label:      "System Logout Hook",
			Path:       systemPrefPath,
			Program:    prefs.LogoutHook,
			ModifiedAt: getFileModTime(systemPrefPath),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("System-wide logout hook: %s", prefs.LogoutHook),
				"hook":        "logout",
				"scope":       "system",
				"script":      prefs.LogoutHook,
				"content":     string(data),
			},
		}
		
		// Read the hook script if it exists
		if scriptData, err := os.ReadFile(prefs.LogoutHook); err == nil {
			item.RawData["scriptContent"] = string(scriptData)
		}
		
		items = append(items, item)
	}

	return items, nil
}

func (s *LoginHooksScanner) scanUserLoginWindow() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home directory: %w", err)
	}

	// User login window preferences
	userPrefPath := filepath.Join(homeDir, "Library", "Preferences", "com.apple.loginwindow.plist")
	
	data, err := os.ReadFile(userPrefPath)
	if err != nil {
		if os.IsNotExist(err) {
			return items, nil
		}
		return nil, fmt.Errorf("reading user login window preferences: %w", err)
	}

	var prefs loginWindowPrefs
	_, err = plist.Unmarshal(data, &prefs)
	if err != nil {
		// Try as a generic map
		var genericPrefs map[string]interface{}
		_, err = plist.Unmarshal(data, &genericPrefs)
		if err != nil {
			return nil, fmt.Errorf("parsing user login window preferences: %w", err)
		}
		
		// Extract hooks from generic map
		if loginHook, ok := genericPrefs["LoginHook"].(string); ok && loginHook != "" {
			prefs.LoginHook = loginHook
		}
		if logoutHook, ok := genericPrefs["LogoutHook"].(string); ok && logoutHook != "" {
			prefs.LogoutHook = logoutHook
		}
	}

	currentUser := os.Getenv("USER")
	if currentUser == "" {
		currentUser = "current"
	}

	// Check for login hook
	if prefs.LoginHook != "" {
		item := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismLoginHook,
			Label:      fmt.Sprintf("User Login Hook (%s)", currentUser),
			Path:       userPrefPath,
			Program:    prefs.LoginHook,
			User:       currentUser,
			ModifiedAt: getFileModTime(userPrefPath),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("User login hook for %s: %s", currentUser, prefs.LoginHook),
				"hook":        "login",
				"scope":       "user",
				"user":        currentUser,
				"script":      prefs.LoginHook,
				"content":     string(data),
			},
		}
		
		// Read the hook script if it exists
		if scriptData, err := os.ReadFile(prefs.LoginHook); err == nil {
			item.RawData["scriptContent"] = string(scriptData)
		}
		
		items = append(items, item)
	}

	// Check for logout hook
	if prefs.LogoutHook != "" {
		item := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismLogoutHook,
			Label:      fmt.Sprintf("User Logout Hook (%s)", currentUser),
			Path:       userPrefPath,
			Program:    prefs.LogoutHook,
			User:       currentUser,
			ModifiedAt: getFileModTime(userPrefPath),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("User logout hook for %s: %s", currentUser, prefs.LogoutHook),
				"hook":        "logout",
				"scope":       "user",
				"user":        currentUser,
				"script":      prefs.LogoutHook,
				"content":     string(data),
			},
		}
		
		// Read the hook script if it exists
		if scriptData, err := os.ReadFile(prefs.LogoutHook); err == nil {
			item.RawData["scriptContent"] = string(scriptData)
		}
		
		items = append(items, item)
	}

	return items, nil
}

func (s *LoginHooksScanner) scanMDMHooks() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Check MDM managed preferences
	mdmPaths := []string{
		"/Library/Managed Preferences/com.apple.loginwindow.plist",
		"/Library/Managed Preferences/root/com.apple.loginwindow.plist",
	}

	for _, mdmPath := range mdmPaths {
		data, err := os.ReadFile(mdmPath)
		if err != nil {
			continue
		}

		var prefs map[string]interface{}
		_, err = plist.Unmarshal(data, &prefs)
		if err != nil {
			continue
		}

		// Check for login hook
		if loginHook, ok := prefs["LoginHook"].(string); ok && loginHook != "" {
			item := scanner.PersistenceItem{
				Mechanism:  scanner.MechanismLoginHook,
				Label:      "MDM Login Hook",
				Path:       mdmPath,
				Program:    loginHook,
				ModifiedAt: getFileModTime(mdmPath),
				RawData: map[string]interface{}{
					"description": fmt.Sprintf("MDM-deployed login hook: %s", loginHook),
					"hook":        "login",
					"scope":       "mdm",
					"script":      loginHook,
					"mdmPath":     mdmPath,
					"content":     string(data),
				},
			}
			items = append(items, item)
		}

		// Check for logout hook
		if logoutHook, ok := prefs["LogoutHook"].(string); ok && logoutHook != "" {
			item := scanner.PersistenceItem{
				Mechanism:  scanner.MechanismLogoutHook,
				Label:      "MDM Logout Hook",
				Path:       mdmPath,
				Program:    logoutHook,
				ModifiedAt: getFileModTime(mdmPath),
				RawData: map[string]interface{}{
					"description": fmt.Sprintf("MDM-deployed logout hook: %s", logoutHook),
					"hook":        "logout",
					"scope":       "mdm",
					"script":      logoutHook,
					"mdmPath":     mdmPath,
					"content":     string(data),
				},
			}
			items = append(items, item)
		}
	}

	return items, nil
}

func (s *LoginHooksScanner) scanViaDefaults() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Check system level hooks via defaults command
	loginCmd := exec.Command("defaults", "read", "com.apple.loginwindow", "LoginHook")
	loginOutput, err := loginCmd.Output()
	if err == nil {
		loginHook := strings.TrimSpace(string(loginOutput))
		if loginHook != "" && loginHook != "0" {
			item := scanner.PersistenceItem{
				Mechanism:  scanner.MechanismLoginHook,
				Label:      "Login Hook (defaults)",
				Path:       "defaults read com.apple.loginwindow",
				Program:    loginHook,
				ModifiedAt: time.Now(),
				RawData: map[string]interface{}{
					"description": fmt.Sprintf("Login hook detected via defaults: %s", loginHook),
					"hook":        "login",
					"scope":       "system",
					"script":      loginHook,
					"method":      "defaults",
				},
			}
			items = append(items, item)
		}
	}

	logoutCmd := exec.Command("defaults", "read", "com.apple.loginwindow", "LogoutHook")
	logoutOutput, err := logoutCmd.Output()
	if err == nil {
		logoutHook := strings.TrimSpace(string(logoutOutput))
		if logoutHook != "" && logoutHook != "0" {
			item := scanner.PersistenceItem{
				Mechanism:  scanner.MechanismLogoutHook,
				Label:      "Logout Hook (defaults)",
				Path:       "defaults read com.apple.loginwindow",
				Program:    logoutHook,
				ModifiedAt: time.Now(),
				RawData: map[string]interface{}{
					"description": fmt.Sprintf("Logout hook detected via defaults: %s", logoutHook),
					"hook":        "logout",
					"scope":       "system",
					"script":      logoutHook,
					"method":      "defaults",
				},
			}
			items = append(items, item)
		}
	}

	return items, nil
}