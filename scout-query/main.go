package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Timeout for the extension server")
	interval = flag.Int("interval", 3, "Interval for the extension server")
	//verbose    = flag.Bool("verbose", false, "Enable verbose logging")
	scoutConf  = flag.String("scout_config", "", "Path to the scout config file")
	socketPath string // Declare package-level variable for socket path
)
var Version string

func main() {
	extensionName := "scout"

	// Parse command-line flags
	flag.Parse()
	// log.Printf("Command-line scout_config flag value: %s\n", *scoutConf)

	if *socket == "" {
		fmt.Fprintf(os.Stderr, "error: --socket flag must be specified\n")
		os.Exit(1)
	}

	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	// Set the package-level socketPath variable in utils.go
	socketPath = *socket

	// Create the extension manager server
	server, err := osquery.NewExtensionManagerServer(extensionName, *socket, serverTimeout, serverPingInterval)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating extension: %v\n", err)
		os.Exit(1)
	}

	// Fetch the Scout Config
	_, err = fetchScoutConfig(*scoutConf) // Assigns to scoutConfig variable
	if err != nil {
		log.Fatalf("failed to fetch scout config: %v\n", err)
	}

	// Ensure cache directory exists
	if err := ensureCacheDir(scoutConfig.CacheDir); err != nil {
		log.Fatalf("failed to ensure cache directory: %v\n", err)
	}

	// Ensure cache database exists
	if err := ensureCacheDB(scoutConfig.CacheDir); err != nil {
		log.Fatalf("failed to ensure cache database: %v\n", err)
	}

	// Register the plugins
	scoutQuickExec := table.NewPlugin("scout_exec", QuickExecColumns(), ScoutQuickExecGenerate)
	scoutScriptCache := table.NewPlugin("scout_cache", CachedScriptsColumns(), ScoutScriptCacheGenerate)

	server.RegisterPlugin(scoutQuickExec)
	server.RegisterPlugin(scoutScriptCache)

	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error running extension: %v\n", err)
		os.Exit(1)
	}
}
