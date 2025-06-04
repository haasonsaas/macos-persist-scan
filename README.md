# macOS Persistence Scanner

A command-line security tool that automatically discovers, analyzes, and reports on macOS persistence mechanisms to help security analysts identify potentially malicious software installations.

## Features

- **Comprehensive Coverage**: Scans all major macOS persistence mechanisms
- **Risk Prioritization**: Intelligent heuristics to highlight suspicious entries
- **Non-Invasive**: Read-only operations ensure system safety
- **Multiple Output Formats**: Table (default), JSON, and SARIF formats
- **Fast**: Parallel scanning completes in under 30 seconds on typical systems

## Installation

```bash
# Clone the repository
git clone https://github.com/haasonsaas/macos-persist-scan.git
cd macos-persist-scan

# Build the tool
make build

# Or install globally
make install
```

## Usage

### Basic Scan
```bash
# Run a standard scan with table output
./macos-persist-scan scan

# Run with JSON output
./macos-persist-scan scan -o json

# Run with SARIF output (for integration with security tools)
./macos-persist-scan scan -o sarif
```

### Command Line Options
```
Flags:
  -o, --output string   Output format (table, json, sarif) (default "table")
  -p, --parallel        Run scanners in parallel (default true)
  -v, --verbose         Enable verbose output
  -h, --help           Help for scan
```

## Persistence Mechanisms Scanned

Comprehensive coverage of all major macOS persistence mechanisms:
- **LaunchAgents** (user and system)
- **LaunchDaemons**
- **Login Items** (user preferences, shared file lists, System Events)
- **Configuration Profiles** (MDM profiles, managed preferences)
- **Cron Jobs** (system crontab, user crontabs, cron.d)
- **Periodic Scripts** (daily/weekly/monthly scripts, periodic.conf)
- **Login/Logout Hooks** (system and user hooks)

## Risk Assessment

The tool uses multiple heuristics to assess risk:

- **Signature Verification**: Checks code signing status
- **Path Analysis**: Identifies suspicious file locations
- **Behavioral Patterns**: Detects malware-like persistence behavior
- **Name Entropy**: Identifies random or obfuscated names

Risk levels:
- **Critical**: Immediate investigation required
- **High**: Suspicious activity detected
- **Medium**: Potentially unwanted behavior
- **Low**: Minor concerns
- **Info**: Informational only

## Exit Codes

- 0: Success, no high-risk items found
- 1: Medium risk items found
- 2: High risk items found
- 3: Critical risk items found

## Building from Source

Requirements:
- Go 1.21 or later
- macOS 10.15 (Catalina) or later

```bash
# Download dependencies
make deps

# Build binary
make build

# Run tests
make test

# Build universal binary (Intel + Apple Silicon)
make universal
```

## Security

This tool performs read-only operations and does not modify any system files or configurations. It may require elevated privileges to scan certain system directories.

## License

MIT License