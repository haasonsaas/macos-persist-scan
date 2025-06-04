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

type LoginItemsScanner struct{}

func NewLoginItemsScanner() *LoginItemsScanner {
	return &LoginItemsScanner{}
}

func (s *LoginItemsScanner) Type() scanner.MechanismType {
	return scanner.MechanismLoginItem
}

func (s *LoginItemsScanner) Scan() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Scan user login items
	userItems, err := s.scanUserLoginItems()
	if err != nil {
		return nil, fmt.Errorf("scanning user login items: %w", err)
	}
	items = append(items, userItems...)

	// Scan shared file list (modern login items)
	sharedItems, err := s.scanSharedFileList()
	if err != nil {
		// Non-fatal error, continue
		fmt.Fprintf(os.Stderr, "Warning: scanning shared file list: %v\n", err)
	} else {
		items = append(items, sharedItems...)
	}

	// Scan login items via LSSharedFileList
	lsItems, err := s.scanLSSharedFileList()
	if err != nil {
		// Non-fatal error
		fmt.Fprintf(os.Stderr, "Warning: scanning LSSharedFileList: %v\n", err)
	} else {
		items = append(items, lsItems...)
	}

	return items, nil
}

type loginItemsPlist struct {
	SessionItems struct {
		CustomListItems []struct {
			Name string `plist:"Name"`
			Alias []byte `plist:"Alias"`
			Data map[string]interface{} `plist:"Data"`
		} `plist:"CustomListItems"`
	} `plist:"SessionItems"`
}

func (s *LoginItemsScanner) scanUserLoginItems() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Check user's login items plist
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home directory: %w", err)
	}

	plistPath := filepath.Join(homeDir, "Library", "Preferences", "com.apple.loginitems.plist")
	
	data, err := os.ReadFile(plistPath)
	if err != nil {
		if os.IsNotExist(err) {
			// File doesn't exist, return empty list
			return items, nil
		}
		return nil, fmt.Errorf("reading login items plist: %w", err)
	}

	var loginItems loginItemsPlist
	_, err = plist.Unmarshal(data, &loginItems)
	if err != nil {
		return nil, fmt.Errorf("parsing login items plist: %w", err)
	}

	for _, item := range loginItems.SessionItems.CustomListItems {
		persistItem := scanner.PersistenceItem{
			Mechanism:   scanner.MechanismLoginItem,
			Label:       item.Name,
			Path:        plistPath,
			ModifiedAt:  getFileModTime(plistPath),
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("Login item: %s", item.Name),
				"Name": item.Name,
				"Data": item.Data,
				"content": string(data),
			},
		}

		// Try to resolve the alias to get the actual path
		if binaryPath := s.resolveAlias(item.Alias); binaryPath != "" {
			persistItem.Program = binaryPath
			persistItem.RawData["description"] = fmt.Sprintf("Login item: %s (%s)", item.Name, binaryPath)
		}

		items = append(items, persistItem)
	}

	return items, nil
}

func (s *LoginItemsScanner) scanSharedFileList() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home directory: %w", err)
	}

	// Check both potential locations
	paths := []string{
		filepath.Join(homeDir, "Library", "Application Support", "com.apple.backgroundtaskmanagementagent", "backgrounditems.btm"),
		"/Library/Application Support/com.apple.backgroundtaskmanagementagent/backgrounditems.btm",
	}

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			// Permission error or other issue, skip
			continue
		}

		// Parse the BTM file (it's a plist)
		var btmData map[string]interface{}
		_, err = plist.Unmarshal(data, &btmData)
		if err != nil {
			continue
		}

		persistItem := scanner.PersistenceItem{
			Mechanism:   scanner.MechanismLoginItem,
			Label:       "Background Task Management Items",
			Path:        path,
			ModifiedAt:  getFileModTime(path),
			RawData:     btmData,
		}
		persistItem.RawData["description"] = "Modern login items managed by Background Task Management"
		persistItem.RawData["content"] = string(data)

		items = append(items, persistItem)
	}

	return items, nil
}

func (s *LoginItemsScanner) scanLSSharedFileList() ([]scanner.PersistenceItem, error) {
	var items []scanner.PersistenceItem

	// Use osascript to query login items
	cmd := exec.Command("osascript", "-e", `tell application "System Events" to get the name of every login item`)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("querying login items via osascript: %w", err)
	}

	itemNames := strings.Split(strings.TrimSpace(string(output)), ", ")
	
	for _, name := range itemNames {
		if name == "" {
			continue
		}

		// Get the path for each login item
		pathCmd := exec.Command("osascript", "-e", fmt.Sprintf(`tell application "System Events" to get the path of login item "%s"`, name))
		pathOutput, err := pathCmd.Output()
		
		itemPath := ""
		if err == nil {
			itemPath = strings.TrimSpace(string(pathOutput))
		}

		persistItem := scanner.PersistenceItem{
			Mechanism:  scanner.MechanismLoginItem,
			Label:      name,
			Path:       "System Events Login Items",
			Program:    itemPath,
			ModifiedAt: time.Now(), // Can't get actual mod time from System Events
			RawData: map[string]interface{}{
				"description": fmt.Sprintf("Login item registered with System Events: %s", name),
				"Name": name,
				"Path": itemPath,
			},
		}

		items = append(items, persistItem)
	}

	return items, nil
}

func (s *LoginItemsScanner) resolveAlias(aliasData []byte) string {
	// This is a simplified alias resolution
	// In reality, macOS aliases are complex binary structures
	// For now, return empty string
	return ""
}

func getFileModTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Now()
	}
	return info.ModTime()
}