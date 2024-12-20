package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type ExecutionCache struct {
	JobID         string
	Script        string
	Args          []string
	ConsoleOut    string
	ErrorOut      string
	ExecutionTime string
	Duration      string
	ScriptHash    string
	FromCache     string
	CacheEnabled  string
	Status        string // "pending", "running", "completed", "failed", "timeout"
}

// CacheMeta is a struct that represents the cache meta file that contains the last time the cache was updated
type CacheMeta struct {
	ScriptHash string    `json:"script_hash"`
	ScriptName string    `json:"script_name"`
	CacheTime  time.Time `json:"cache_time"`
}

func loadSignatureFromCache(cacheKey string, cacheDir string) ([]byte, error) {
	signatureFilePath := getSignatureFilePath(cacheKey, cacheDir)
	signature, err := os.ReadFile(signatureFilePath)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// Determine the OS-specific subdirectory based on runtime.GOOS
func getOSSubDir() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		// For Linux and other UNIX-like systems, default to "linux"
		return "linux"
	}
}

func getScriptURL(serverURL, scriptName string) string {
	osDir := getOSSubDir()
	// Construct the full URL including the OS-specific subdirectory
	// For example: https://yourserver.com/scripts/windows/myscript.ps1 on Windows
	//              https://yourserver.com/scripts/linux/myscript.sh on Linux
	//              https://yourserver.com/scripts/darwin/myscript.sh on macOS
	//fmt.Sprintf("%s/%s", strings.TrimRight(serverURL, "/"), url.PathEscape(scriptName))
	return fmt.Sprintf("%s/%s/%s",
		strings.TrimRight(serverURL, "/"), osDir, url.PathEscape(scriptName))
}

// Helper function to get signature file path
func getSignatureFilePath(cacheKey string, cacheDir string) string {

	return filepath.Join(cacheDir, fmt.Sprintf("%s.script.sig", cacheKey))
}

// Helper function to load script from cache
func loadScriptFromCache(cacheKey string, cacheDir string) ([]byte, CacheMeta, error) {
	cacheFilePath := getCacheFilePath(cacheKey, cacheDir)

	//log.Printf(" %s", cacheFilePath)
	//check if the cache file exists
	if _, err := os.Stat(cacheFilePath); os.IsNotExist(err) {
		return nil, CacheMeta{}, fmt.Errorf("cache file does not exist")
	}

	data, err := os.ReadFile(cacheFilePath)
	if err != nil {
		return nil, CacheMeta{}, err
	}

	// Read metadata file
	metadataFilePath := cacheFilePath + ".meta"
	metadataData, err := os.ReadFile(metadataFilePath)
	if err != nil {
		return nil, CacheMeta{}, err
	}

	var metadata struct {
		ScriptHash string    `json:"script_hash"`
		ScriptName string    `json:"script_name"`
		CacheTime  time.Time `json:"cache_time"`
	}
	err = json.Unmarshal(metadataData, &metadata)
	if err != nil {
		return nil, CacheMeta{}, err
	}

	return data, metadata, nil
}

func saveScriptToCache(cacheKey string, script Script, signature []byte, cacheDir string) error {

	scriptHash := script.Hash
	scriptName := script.Name
	data := script.Contents

	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		err = os.MkdirAll(cacheDir, 0755)
		if err != nil {
			return err
		}
	}

	cacheFilePath := getCacheFilePath(cacheKey, cacheDir)
	if _, err := os.Stat(cacheFilePath); err == nil {
		err = os.Remove(cacheFilePath)
		if err != nil {
			return err
		}
	}
	err := os.WriteFile(cacheFilePath, data, 0600)
	if err != nil {
		return err
	}

	metadata := CacheMeta{
		ScriptHash: scriptHash,
		ScriptName: scriptName,
		CacheTime:  time.Now(),
	}
	metadataData, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	if _, err := os.Stat(cacheFilePath + ".meta"); err == nil {
		err = os.Remove(cacheFilePath + ".meta")
		if err != nil {
			return err
		}
	}

	metadataFilePath := cacheFilePath + ".meta"
	err = os.WriteFile(metadataFilePath, metadataData, 0600)
	if err != nil {
		return err
	}

	if _, err := os.Stat(getSignatureFilePath(cacheKey, cacheDir)); err == nil {
		err = os.Remove(getSignatureFilePath(cacheKey, cacheDir))
		if err != nil {
			return err
		}
	}
	signatureFilePath := cacheFilePath + ".sig"
	// Save the signature to cache
	err = os.WriteFile(signatureFilePath, signature, 0600)
	if err != nil {
		return err
	}

	return nil
}

// Modified removeScriptFromCache to remove signature file
func removeScriptFromCache(cacheKey string, cacheDir string) {
	cacheFilePath := getCacheFilePath(cacheKey, cacheDir)
	os.Remove(cacheFilePath)
	os.Remove(cacheFilePath + ".meta")
	os.Remove(getSignatureFilePath(cacheKey, cacheDir))
}

// Helper function to get cache file path based on cache key
func getCacheFilePath(cacheKey string, cacheDir string) string {
	return filepath.Join(cacheDir, fmt.Sprintf("%s.script", cacheKey))
}

// Helper function to get cache key based on URL
func getCacheKey(url string) string {
	hasher := sha256.New()
	hasher.Write([]byte(url))
	return hex.EncodeToString(hasher.Sum(nil))
}

// Helper function to get script hash from server
func getScriptHashFromServer(serverURL, scriptName string) (string, error) {
	hashURL := fmt.Sprintf("%s/hash/%s", strings.TrimRight(serverURL, "/"), url.PathEscape(scriptName))
	resp, err := http.Get(hashURL)
	if err != nil {
		return "", fmt.Errorf("failed to fetch script hash: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to fetch script hash: received status code %d", resp.StatusCode)
	}

	var result struct {
		ScriptHash string `json:"script_hash"`
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read script hash response: %v", err)
	}
	err = json.Unmarshal(body, &result)
	if err != nil {
		return "", fmt.Errorf("failed to parse script hash JSON: %v", err)
	}

	return result.ScriptHash, nil
}

// Helper function to create a sqlite3 database for caching, user passes in the path to the database
func createCacheDB(dbPath string) error {
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		file, err := os.Create(dbPath)
		if err != nil {
			return err
		}
		file.Close()
	}

	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}

	defer db.Close()

	//create teh execution cache table based on the ExecutionCache struct
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS execution_cache (
		job_id TEXT PRIMARY KEY,
		script TEXT,
		args TEXT,
		console_out TEXT,
		error_out TEXT,
		execution_time TEXT,
		duration TEXT,
		script_hash TEXT,
		from_cache TEXT,
		cache_enabled TEXT,
		status TEXT
	)`)

	if err != nil {
		return err
	}

	return nil
}
