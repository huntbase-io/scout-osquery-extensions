package main

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/kluctl/go-embed-python/python"
	"github.com/osquery/osquery-go/plugin/table"
)

// Script is a struct that represents a script that can be run on a target
type Script struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Contents    []byte `json:"contents"`
	Hash        string `json:"hash"`
	Cached      bool   `json:"cached"`
}

type ExecutionResult struct {
	JobID         string `json:"job_id"`
	ScriptName    string `json:"script_name"`
	Args          string `json:"args"`
	ConsoleOut    string `json:"console_out"`
	ErrorOut      string `json:"error_out"`
	ExecutionTime string `json:"execution_time"`
	Duration      string `json:"duration"`
	ScriptHash    string `json:"script_hash"`
	FromCache     string `json:"from_cache"`
	CacheEnabled  string `json:"cache_enabled"`
	Status        string `json:"status"` // "pending", "running", "completed", "failed", "timeout"
}

func ScoutQuickExecGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	scriptNames := processContextConstraints(queryContext, "script_name")
	if len(scriptNames) == 0 {
		return nil, fmt.Errorf("no script specified in the query")
	}

	if len(scriptNames) > 1 {
		return nil, fmt.Errorf("only one script can be executed at a time")
	}

	scriptName := scriptNames[0]
	argsList := processContextConstraints(queryContext, "args")

	// Log cache constraint if it exists
	cacheList := processContextConstraints(queryContext, "from_cache")
	useCache := "false"
	if len(cacheList) > 0 {
		useCache = cacheList[0]
	}
	cacheBool := processBoolConstraint(useCache)

	script, err := getScript(scriptName, cacheBool)
	if err != nil {
		return nil, fmt.Errorf("failed to get script: %v", err)
	}

	var result ExecutionResult

	// Use ExecTimeout from config
	execTimeout := int(scoutConfig.ExecTimeout.Seconds())
	if execTimeout == 0 {
		execTimeout = 30 // Default to 30 seconds if not set
	}
	log.Printf("Executing script: %s with args: %v\n", scriptName, argsList)

	result, err = executeScript(script, argsList, execTimeout)
	if err != nil {
		log.Printf("%+v", result)
		return nil, fmt.Errorf("failed to execute script: %v", err)
	}

	if script.Cached {
		result.FromCache = "true"
	} else {
		result.FromCache = "false"
	}

	// Determine columns and process output
	consoleLines := strings.Split(result.ConsoleOut, "\n")
	if len(consoleLines) == 0 {
		return nil, fmt.Errorf("no output from script")
	}

	var rows []map[string]string
	var columns []string

	// Check if the first line is valid JSON
	var firstLineData map[string]interface{}
	isValidJSON := json.Unmarshal([]byte(consoleLines[0]), &firstLineData) == nil

	if isValidJSON {
		// Use JSON keys as column names
		for key := range firstLineData {
			columns = append(columns, key)
		}

		// Parse each line as JSON and add to rows
		for _, line := range consoleLines {
			if strings.TrimSpace(line) == "" {
				continue // Skip empty lines
			}

			var lineData map[string]string
			if err := json.Unmarshal([]byte(line), &lineData); err != nil {
				continue // Skip invalid JSON lines
			}

			row := map[string]string{
				"script_name": result.ScriptName,
				"args":        result.Args,
				"from_cache":  useCache,
				"status":      result.Status,
				"columns":     strings.Join(columns, ","),
			}

			// Add JSON fields to the row
			for key, value := range lineData {
				row[key] = value
			}

			rows = append(rows, row)
		}
	} else {
		// Treat as plain text
		columns = []string{"console_out"}
		for _, line := range consoleLines {
			if strings.TrimSpace(line) == "" {
				continue // Skip empty lines
			}

			rows = append(rows, map[string]string{
				"script_name":    result.ScriptName,
				"args":           result.Args,
				"console_out":    line,
				"error_out":      result.ErrorOut,
				"execution_time": result.ExecutionTime,
				"duration":       result.Duration,
				"script_hash":    result.ScriptHash,
				"from_cache":     useCache,
				"status":         result.Status,
				"columns":        strings.Join(columns, ","),
			})
		}
	}

	return rows, nil
}

func ScoutScriptCacheGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	// Use scoutConfig.CacheDir
	cacheDir := scoutConfig.CacheDir
	// Create the cache directory if it does not exist
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		err = os.MkdirAll(cacheDir, 0755)
		if err != nil {
			return nil, fmt.Errorf("failed to create cache directory: %v", err)
		}
	}

	files, err := os.ReadDir(cacheDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read cache directory: %v", err)
	}

	var results []map[string]string

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		if !strings.HasSuffix(file.Name(), ".meta") {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", cacheDir, file.Name())
		fileInfo, err := os.Stat(filePath)
		if err != nil {
			log.Printf("Failed to stat file: %v", err)
			continue
		}

		var script Script
		var scriptMeta CacheMeta

		// Process meta file
		metaData, err := os.ReadFile(filePath)
		if err != nil {
			log.Printf("Failed to read meta file: %v", err)
			continue
		}
		err = json.Unmarshal(metaData, &scriptMeta)
		if err != nil {
			log.Printf("Failed to unmarshal meta file: %v", err)
			continue
		}
		script.Name = scriptMeta.ScriptName
		script.Hash = scriptMeta.ScriptHash
		script.Description = ""

		scriptFilePath := strings.TrimSuffix(filePath, ".meta")
		// Calculate the SHA256 of script file contents
		scriptData, err := os.ReadFile(scriptFilePath)
		if err != nil {
			log.Printf("Failed to read script file: %v", err)
			continue
		}
		hasher := sha256.New()
		hasher.Write(scriptData)
		hashed := hasher.Sum(nil)
		script.Hash = hex.EncodeToString(hashed)

		results = append(results, map[string]string{
			"name":         script.Name,
			"description":  script.Description,
			"hash":         script.Hash,
			"last_updated": fileInfo.ModTime().Format(time.RFC3339),
			"cache":        "true",
			"path":         filePath,
		})
	}

	return results, nil
}

func executeScript(script Script, argsList []string, exec_timeout int) (result ExecutionResult, err error) {
	execResult := ExecutionResult{
		JobID:      "quick_exec",
		ScriptName: script.Name,
		Args:       strings.Join(argsList, " "),
		Status:     "running",
		ScriptHash: script.Hash,
	}

	// Determine the file extension based on the script type
	var fileExt string

	switch {
	case isPowerShellScript(script.Name):
		fileExt = ".ps1"
	case isBatchScript(script.Name):
		fileExt = ".bat"
	case isVBScript(script.Name):
		fileExt = ".vbs"
	case isPythonScript(script.Name):
		fileExt = ".py"
	case isShellScript(script.Name):
		fileExt = ".sh"
	default:
		fileExt = "" // Default or handle unsupported types
	}
	log.Printf("Script file extension: %s\n", fileExt)
	log.Printf("Path to script: %s\n", script.Name)
	// Write the script data to a temp file
	tmpFile, err := os.CreateTemp("", "remote_script_*"+fileExt)
	if err != nil {
		execResult.ErrorOut = fmt.Sprintf("Failed to create temp file: %v", err)
		execResult.Status = "failed"
		return execResult, err
	}
	defer os.Remove(tmpFile.Name())

	// Write the script content to the temp file
	_, err = tmpFile.Write([]byte(script.Contents))
	if err != nil {
		execResult.ErrorOut = fmt.Sprintf("Failed to write script to temp file: %v", err)
		execResult.Status = "failed"
		return execResult, err
	}
	tmpFile.Close()

	// Make the script executable (for Unix-based systems)
	if runtime.GOOS != "windows" {
		err = os.Chmod(tmpFile.Name(), 0700)
		if err != nil {
			execResult.ErrorOut = fmt.Sprintf("Failed to set script executable: %v", err)
			execResult.Status = "failed"
			return execResult, err
		}
	}

	// Create a context with a timeout to enforce guardrails
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(exec_timeout)*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	var cmdArgs []string

	var scriptArgs string
	if len(argsList) > 0 {
		scriptArgs = strings.Join(argsList, " ")
	}

	// Split scriptArgs into a slice, considering quotes
	argsSlice := parseArguments(scriptArgs)

	switch runtime.GOOS {
	case "windows":
		if isPowerShellScript(script.Name) {
			//execute the tmp file with args as a powershell script using hte powershell.go module
			ps := New()
			stdOut, stdErr, err := ps.execute(tmpFile.Name(), argsList...)
			if err != nil {
				execResult.ErrorOut = stdErr
				execResult.Status = "failed"
				return execResult, err
			}
			execResult.ConsoleOut = stdOut
			execResult.ErrorOut = stdErr
			execResult.Status = "completed"
			return execResult, err

		} else if isBatchScript(script.Name) {
			cmdArgs = append([]string{"/C", tmpFile.Name()}, argsList...)
			cmd = exec.CommandContext(ctx, "cmd.exe", cmdArgs...)
		} else if isVBScript(script.Name) {
			cmdArgs = append([]string{tmpFile.Name()}, argsList...)
			cmd = exec.CommandContext(ctx, "cscript.exe", cmdArgs...)
		} else if isPythonScript(script.Name) {
			cmdArgs = append([]string{tmpFile.Name()}, argsList...)
			ep, err := python.NewEmbeddedPython("example")
			if err != nil {
				panic(err)
			}
			cmd, err := ep.PythonCmd(cmdArgs...)
			if err != nil {
				panic(err)
			}
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err = cmd.Run()
			if err != nil {
				panic(err)
			}
		} else {
			execResult.ErrorOut = "Unsupported script type on Windows"
			execResult.Status = "failed"
			return execResult, err
		}
	case "darwin", "linux":
		if isShellScript(script.Name) {
			cmdArgs = append([]string{tmpFile.Name()}, argsSlice...)
			cmd = exec.CommandContext(ctx, "/bin/bash", cmdArgs...)
		} else if isPythonScript(script.Name) {
			cmdArgs = append([]string{tmpFile.Name()}, argsSlice...)
			cmd = exec.CommandContext(ctx, "python3", cmdArgs...)
		} else {
			execResult.ErrorOut = "Unsupported script type on Unix"
			execResult.Status = "failed"
			return execResult, err
		}
	default:
		execResult.ErrorOut = "Unsupported OS"
		execResult.Status = "failed"
		return execResult, err
	}

	// If not PowerShell inline execution, proceed with the usual command execution flow
	if cmd != nil {
		execResult.JobID = "quick_exec"
		execResult, err = startCommandExecution(cmd, execResult, ctx)
	}

	return execResult, err
}

func getScript(scriptName string, useCache bool) (Script, error) {
	// Use scoutConfig variables directly
	serverURL := scoutConfig.ServerURL
	publicKeyStr := scoutConfig.PublicKey
	cacheWindow := scoutConfig.CacheWindow
	cacheDir := scoutConfig.CacheDir

	// Compute the cache key (script hash)
	var scriptData []byte
	var scriptHash string
	var fromCache bool
	var cacheErr error
	var cacheTimestamp time.Time
	var cacheEnabled = true

	cacheValid := false

	// Construct the full URL with URL-encoded script name
	//fullURL := fmt.Sprintf("%s/%s", strings.TrimRight(serverURL, "/"), url.PathEscape(scriptName))
	fullURL := getScriptURL(serverURL, scriptName)
	cacheKey := getCacheKey(fullURL)
	script := Script{}
	if useCache {
		// Attempt to load script from cache
		//check the file exists
		cacheMutex.Lock()
		var scriptMeta CacheMeta
		scriptData, scriptMeta, cacheErr = loadScriptFromCache(cacheKey, cacheDir)
		scriptHash = scriptMeta.ScriptHash
		cacheTimestamp = scriptMeta.CacheTime
		scriptName = scriptMeta.ScriptName
		if cacheErr == nil {
			log.Printf("Script loaded from cache: %s\n", scriptName)
		} else {
			log.Printf("Failed to load script from cache: %v\n", cacheErr)
			cacheValid = false
		}
		cacheMutex.Unlock()
		cacheValid := false
		if cacheErr == nil {
			// Check if cache has expired
			if time.Since(cacheTimestamp) < cacheWindow {
				// Check with server if the script hash is still current
				currentHash, err := getScriptHashFromServer(serverURL, scriptName)
				if err == nil && currentHash == scriptHash {
					// check that the signature file exists, the signature is valid, and the script hash matches
					signatureFilePath := getSignatureFilePath(cacheKey, cacheDir)
					if _, err := os.Stat(signatureFilePath); err == nil {
						signature, err := loadSignatureFromCache(cacheKey, cacheDir)
						if err == nil {
							// Parse the public key
							block, _ := pem.Decode([]byte(publicKeyStr))
							if block != nil {
								pub, err := x509.ParsePKIXPublicKey(block.Bytes)
								if err == nil {
									rsaPub, ok := pub.(*rsa.PublicKey)
									if ok {
										// Compute script hash
										hasher := sha256.New()
										hasher.Write(scriptData)
										hashed := hasher.Sum(nil)
										scriptHash = hex.EncodeToString(hashed)

										// Verify the script signature
										err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed, signature)
										if err == nil {
											cacheValid = true
											fromCache = true
											script = Script{
												Name:     scriptName,
												Contents: scriptData,
												Hash:     scriptHash,
												Cached:   fromCache,
											}
											return script, nil
										} else {
											log.Printf("Script signature verification failed: %v\n", err)
										}
									} else {
										log.Printf("Public key is not RSA\n")
									}
								} else {
									log.Printf("Failed to parse public key: %v\n", err)
								}
							} else {
								log.Printf("Failed to parse public key PEM\n")
							}
						} else {
							log.Printf("Failed to load signature from cache: %v\n", err)
						}
					} else {
						log.Printf("Signature file not found in cache: %v\n", err)
					}
				} else if err == nil {
					log.Printf("Script hash mismatch: %s != %s\n", currentHash, scriptHash)
				} else {
					log.Printf("Error fetching script hash from server: %v\n", err)
				}
			} else {
				log.Printf("Cache expired for script: %s\n", scriptName)
			}
		}

		if !cacheValid || !useCache || cacheErr != nil {
			fromCache = false
			// Remove invalid cache entry
			cacheMutex.Lock()
			removeScriptFromCache(cacheKey, cacheDir)
			cacheMutex.Unlock()
		}
	}

	if !cacheValid {
		// Fetch the script
		log.Printf("Fetching script from server at url: %s\n", fullURL)
		respHTTP, err := http.Get(fullURL)
		if err != nil {
			return Script{}, fmt.Errorf("failed to fetch script: %v", err)
		}
		defer respHTTP.Body.Close()

		if respHTTP.StatusCode != http.StatusOK {
			return Script{}, fmt.Errorf("failed to fetch script: received status code %d", respHTTP.StatusCode)
		}

		scriptData, err = io.ReadAll(respHTTP.Body)
		if err != nil {
			return Script{}, fmt.Errorf("failed to read script data: %v", err)
		}

		// Get the signature from the response header
		signatureHex := respHTTP.Header.Get("X-Signature")
		if signatureHex == "" {
			return Script{}, fmt.Errorf("no signature in response header")
		}

		// Decode the signature from hex
		signature, err := hex.DecodeString(signatureHex)
		if err != nil {
			return Script{}, fmt.Errorf("failed to decode signature: %v", err)
		}

		// Parse the public key
		block, _ := pem.Decode([]byte(publicKeyStr))
		if block == nil {
			return Script{}, fmt.Errorf("failed to parse public key PEM")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return Script{}, fmt.Errorf("failed to parse public key: %v", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return Script{}, fmt.Errorf("public key is not rsa")
		}

		// Compute script hash
		hasher := sha256.New()
		hasher.Write(scriptData)
		hashed := hasher.Sum(nil)
		scriptHash = hex.EncodeToString(hashed)

		// Verify the script signature
		err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hashed, signature)
		if err != nil {
			return Script{}, fmt.Errorf("Script signature verification failed: %v", err)
		}

		// Construct the script object
		script = Script{
			Name:     scriptName,
			Contents: scriptData,
			Hash:     scriptHash,
			Cached:   fromCache,
		}

		// Save script to cache - Currently cache is enabled by default, need to wipe cache after a certain time
		if cacheEnabled {
			cacheMutex.Lock()
			err = saveScriptToCache(cacheKey, script, signature, cacheDir)
			cacheMutex.Unlock()
			if err != nil {
				return Script{}, fmt.Errorf("failed to save script to cache: %v", err)
			}
		}
		log.Printf("Script fetched and verified from server: %s\n", scriptName)
	}

	return script, nil
}

// Helper function to handle actual command execution and capture stdout and stderr
func startCommandExecution(cmd *exec.Cmd, execResult ExecutionResult, ctx context.Context) (results ExecutionResult, err error) {
	// Capture stdout and stderr
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		execResult.ErrorOut = fmt.Sprintf("Failed to capture stdout: %v", err)
		execResult.Status = "failed"
		return execResult, err // Return early if we can't capture stdout
	}

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		execResult.ErrorOut = fmt.Sprintf("Failed to capture stderr: %v", err)
		execResult.Status = "failed"
		return execResult, err
	}

	// Start the command execution
	startTime := time.Now()
	if err := cmd.Start(); err != nil {
		execResult.ErrorOut = fmt.Sprintf("Failed to start command: %v", err)
		execResult.Status = "failed"
		return execResult, err
	}

	// Read outputs concurrently
	stdoutChan := make(chan string)
	stderrChan := make(chan string)

	go func() {
		out, _ := io.ReadAll(stdoutPipe)
		stdoutChan <- string(out)
	}()

	go func() {
		out, _ := io.ReadAll(stderrPipe)
		stderrChan <- string(out)
	}()

	// Wait for command completion or context timeout
	err = cmd.Wait()

	// Check for timeout
	if ctx.Err() == context.DeadlineExceeded {
		execResult.ErrorOut = "Script execution timed out"
		execResult.Status = "timeout"
		_ = cmd.Process.Kill() // Ensure the process is killed
		return execResult, err
	}

	// Collect outputs
	execResult.ConsoleOut = <-stdoutChan
	execResult.ErrorOut += <-stderrChan

	//log.Printf("Console output: %v\n", execResult.ConsoleOut)
	// Calculate execution time
	execResult.ExecutionTime = startTime.Format(time.RFC3339)
	execResult.Duration = time.Since(startTime).String()

	if err != nil {
		execResult.ErrorOut += fmt.Sprintf("\nScript execution failed: %v", err)
		execResult.Status = "failed"
	} else {
		execResult.Status = "completed"
	}

	return execResult, err
}

func isVBScript(script string) bool {
	return strings.HasSuffix(strings.ToLower(script), ".vbs") || strings.HasSuffix(strings.ToLower(script), ".vbscript")
}

func isBatchScript(scriptName string) bool {
	return strings.HasSuffix(strings.ToLower(scriptName), ".bat") || strings.HasSuffix(strings.ToLower(scriptName), ".cmd")
}

func isShellScript(scriptName string) bool {
	return strings.HasSuffix(strings.ToLower(scriptName), ".sh")
}

func isPythonScript(scriptName string) bool {
	return strings.HasSuffix(strings.ToLower(scriptName), ".py") || strings.HasSuffix(strings.ToLower(scriptName), ".pyc")
}

func isPowerShellScript(script string) bool {
	return strings.HasSuffix(strings.ToLower(script), ".ps1") || strings.HasSuffix(strings.ToLower(script), ".psm1") || strings.HasSuffix(strings.ToLower(script), ".psd1")
}

func parseArguments(args string) []string {
	// First, try to unmarshal the input string as a JSON array of strings
	var array []string
	if err := json.Unmarshal([]byte(args), &array); err == nil {
		// Successfully parsed as JSON array
		return array
	}

	// If not a JSON array, proceed with existing parsing logic
	var result []string
	var currentArg strings.Builder
	var inQuotes bool
	var quoteChar rune

	for i, c := range args {
		switch c {
		case ' ', '\t':
			if inQuotes {
				currentArg.WriteRune(c)
			} else if currentArg.Len() > 0 {
				result = append(result, currentArg.String())
				currentArg.Reset()
			}
		case '"', '\'':
			if inQuotes && c == quoteChar {
				inQuotes = false
			} else if !inQuotes {
				inQuotes = true
				quoteChar = c
			} else {
				currentArg.WriteRune(c)
			}
		default:
			currentArg.WriteRune(c)
		}

		// Append the last argument at the end of the string
		if i == len(args)-1 && currentArg.Len() > 0 {
			result = append(result, currentArg.String())
		}
	}
	return result
}
