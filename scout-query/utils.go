package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

type ScoutConfig struct {
	ServerURL   string        `json:"server_url"`
	PublicKey   string        `json:"public_key"`
	CacheWindow time.Duration `json:"cache_window"`
	ExecTimeout time.Duration `json:"exec_timeout"`
	CacheDir    string        `json:"cache_dir"`
}

var (
	cacheMutex   sync.Mutex
	cacheDirName = "scout_cache"
	scoutConfig  ScoutConfig // Package-level variable to hold the config
)

func fetchScoutConfig(scoutConfFlag string) (config ScoutConfig, err error) {
	config = ScoutConfig{}

	var configPath string
	if scoutConfFlag != "" {
		// Use the path provided via the command-line flag
		configPath = scoutConfFlag
	} else {
		// Attempt to read from osquery.conf or scout.conf
		client, err := osquery.NewClient(socketPath, 5*time.Second)
		if err != nil {
			return config, fmt.Errorf("error creating osquery client: %v", err)
		}
		defer client.Close()

		// Try to get config_path from osquery_flags
		resp, err := client.Query("SELECT value FROM osquery_flags WHERE name='config_path';")
		if err != nil {
			return config, fmt.Errorf("failed to query osquery_flags for config_path: %v", err)
		}

		if len(resp.Response) == 0 {
			// Use the current directory that osquery is running from if config_path is not set
			executablePath, err := os.Executable()
			if err != nil {
				return config, fmt.Errorf("failed to get executable path: %v", err)
			}
			configPath = filepath.Join(filepath.Dir(executablePath), "osquery.conf")
		} else {
			configPath = resp.Response[0]["value"]
		}
	}

	// Read the config file
	configData, err := os.ReadFile(configPath)
	if err != nil {
		// Try reading scout.conf in the same directory if the initial configPath fails
		scoutConfigPath := filepath.Join(filepath.Dir(configPath), "scout.conf")
		configData, err = os.ReadFile(scoutConfigPath)
		if err != nil {
			return config, fmt.Errorf("failed to read config file: %v", err)
		}
	}

	// Parse the config JSON
	var configMap map[string]interface{}
	err = json.Unmarshal(configData, &configMap)
	if err != nil {
		return config, fmt.Errorf("failed to parse config json: %v", err)
	}

	// Check if the scout section exists
	scoutOptions, ok := configMap["scout"].(map[string]interface{})
	if !ok {
		// Try reading scout.conf if the scout section is not found in the initial configPath
		log.Printf("Path to config file: %s\n", configPath)
		scoutConfigPath := filepath.Join(filepath.Dir(configPath), "scout.conf")
		configData, err = os.ReadFile(scoutConfigPath)
		if err != nil {
			return config, fmt.Errorf("failed to read scout config file: %v", err)
		}

		err = json.Unmarshal(configData, &configMap)
		if err != nil {
			return config, fmt.Errorf("failed to parse scout config json: %v", err)
		}

		scoutOptions, ok = configMap["scout"].(map[string]interface{})
		if !ok {
			return config, fmt.Errorf("no 'scout' section in config")
		}
	}

	// Get the server URL, public key, and cache window from the config
	config.ServerURL, ok = scoutOptions["script_server_url"].(string)
	if !ok {
		return config, fmt.Errorf("no 'script_server_url' in 'scout' section")
	}

	config.PublicKey, ok = scoutOptions["public_key"].(string)
	if !ok {
		return config, fmt.Errorf("no 'public_key' in 'scout' section")
	}

	config.CacheWindow = 3600 * time.Second
	if val, ok := scoutOptions["cache_window_seconds"].(float64); ok {
		config.CacheWindow = time.Duration(val) * time.Second
	}

	config.ExecTimeout = 60 * time.Second
	if val, ok := scoutOptions["exec_timeout_seconds"].(float64); ok {
		config.ExecTimeout = time.Duration(val) * time.Second
	}

	// Set the CacheDir to the directory of the config path
	config.CacheDir = filepath.Join(filepath.Dir(configPath), cacheDirName)
	if dir, ok := scoutOptions["cache_dir"].(string); ok && dir != "" {
		config.CacheDir = dir
	}

	// Assign to the package-level variable
	scoutConfig = config

	return config, nil
}

func processContextConstraints(queryContext table.QueryContext, columnName string) []string {
	var constraints []string
	if constraintList, present := queryContext.Constraints[columnName]; present {
		for _, constraint := range constraintList.Constraints {
			// =
			if constraint.Operator == table.OperatorEquals {
				constraints = append(constraints, constraint.Expression)
			}
		}
	}
	return constraints
}

func processBoolConstraint(val string) bool {
	switch strings.ToLower(val) {
	case "0", "false":
		return false
	case "1", "true":
		return true
	}
	return false
}

// ensureCacheDir ensures that the cache directory exists
func ensureCacheDir(cacheDir string) error {
	if cacheDir == "" {
		cacheDir = filepath.Join(os.TempDir(), cacheDirName)
	}
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, 0755); err != nil {
			return fmt.Errorf("failed to create cache directory %s: %v", cacheDir, err)
		}
	}
	return nil
}

// ensureCacheDB ensures that the cache database exists
func ensureCacheDB(cacheDir string) error {
	dbPath := filepath.Join(cacheDir, "scout_cache.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		if err := createCacheDB(dbPath); err != nil {
			return fmt.Errorf("failed to create cache database %s: %v", dbPath, err)
		}
	}
	return nil
}
