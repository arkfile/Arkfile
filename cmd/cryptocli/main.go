// Cryptocli - OPAQUE-exclusive command-line tool for Arkfile
// This tool is scoped exclusively for OPAQUE envelope inspection, file format validation,
// and post-quantum migration utilities, eliminating legacy password-based operations.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/84adam/arkfile/cmd/cryptocli/commands"
)

var (
	version = "1.0.0"
	commit  = "dev"
	date    = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Global flags
	var (
		verboseFlag = flag.Bool("verbose", false, "Enable verbose output")
		helpFlag    = flag.Bool("help", false, "Show help information")
		versionFlag = flag.Bool("version", false, "Show version information")
	)

	// Parse global flags first
	flag.CommandLine.Parse(os.Args[2:])

	if *versionFlag {
		printVersion()
		return
	}

	if *helpFlag {
		printUsage()
		return
	}

	command := os.Args[1]
	args := os.Args[2:]

	// Remove global flags from args for command parsing
	filteredArgs := []string{}
	skipNext := false
	for _, arg := range args {
		if skipNext {
			skipNext = false
			continue
		}
		if arg == "-verbose" || arg == "--verbose" ||
			arg == "-help" || arg == "--help" ||
			arg == "-version" || arg == "--version" {
			continue
		}
		if arg == "-v" || arg == "-h" {
			continue
		}
		filteredArgs = append(filteredArgs, arg)
	}

	// Configure verbose output
	commands.SetVerbose(*verboseFlag)

	// Execute command
	switch command {
	case "inspect":
		if err := commands.InspectEnvelope(filteredArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "validate":
		if err := commands.ValidateFileFormat(filteredArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "pq-status":
		if err := commands.PostQuantumStatus(filteredArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "pq-prepare":
		if err := commands.PreparePostQuantumMigration(filteredArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "health":
		if err := commands.HealthCheck(filteredArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	case "opaque-status":
		if err := commands.OPAQUEStatus(filteredArgs); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`cryptocli - OPAQUE-exclusive administrative tool for Arkfile v%s

USAGE:
    cryptocli [GLOBAL_FLAGS] <command> [COMMAND_FLAGS] [ARGS]

GLOBAL FLAGS:
    -verbose, -v    Enable verbose output
    -help, -h       Show this help message
    -version        Show version information

COMMANDS:
    inspect         Inspect OPAQUE envelope contents
    validate        Validate file format compatibility
    pq-status       Check post-quantum readiness status
    pq-prepare      Prepare system for post-quantum migration
    health          Check OPAQUE system health
    opaque-status   Show OPAQUE system status and configuration

EXAMPLES:
    # Inspect an OPAQUE envelope
    cryptocli inspect envelope.dat

    # Validate file format compatibility
    cryptocli validate /path/to/encrypted/file

    # Check post-quantum migration status
    cryptocli pq-status

    # Prepare for post-quantum migration
    cryptocli pq-prepare --check-only

    # Check system health
    cryptocli health --detailed

    # Show OPAQUE system status
    cryptocli opaque-status --detailed

Use 'cryptocli <command> -help' for command-specific help.

SCOPE:
    This tool is exclusively designed for OPAQUE authentication operations,
    post-quantum migration utilities, and file format validation. It does
    not support legacy password-based operations and maintains focus on
    administrative tasks for cryptographic transitions.

`, version)
}

func printVersion() {
	fmt.Printf("cryptocli version %s\n", version)
	fmt.Printf("commit: %s\n", commit)
	fmt.Printf("built: %s\n", date)
	fmt.Printf("OPAQUE-exclusive administrative tool\n")
}
