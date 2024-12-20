package main

import (
	"bytes"
	"log"
	"os/exec"
)

// PowerShell struct
type PowerShell struct {
	powerShell string
}

// New create new session
func New() *PowerShell {
	ps, _ := exec.LookPath("powershell.exe")
	return &PowerShell{
		powerShell: ps,
	}
}

func (p *PowerShell) execute(scriptPath string, args ...string) (stdOut string, stdErr string, err error) {
	// Combine the script path and additional arguments
	allArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-NonInteractive", "-File", scriptPath}, args...)

	log.Printf("Executing the following command: %v %v", p.powerShell, allArgs)
	cmd := exec.Command(p.powerShell, allArgs...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	return stdOut, stdErr, err
}
