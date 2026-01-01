package strategy

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/theflakes/StoW/pkg/types"
)

// IntelligentFieldMapper provides smart field mapping for unmapped Sigma fields
// This is particularly useful for Linux auditd rules where Sigma doesn't specify exact fields
type IntelligentFieldMapper struct {
	Config   *types.Config
	Product  string
	Category string
}

// Common Linux commands that typically appear in a0
var commonLinuxCommands = map[string]bool{
	// File operations
	"cat": true, "cp": true, "mv": true, "rm": true, "touch": true, "chmod": true,
	"chown": true, "chgrp": true, "mkdir": true, "rmdir": true, "ln": true,
	// Compression
	"tar": true, "gzip": true, "gunzip": true, "zip": true, "unzip": true, "bzip2": true,
	// System utilities
	"dd": true, "truncate": true, "split": true, "cut": true, "sort": true, "uniq": true,
	// Process/system
	"ps": true, "top": true, "kill": true, "killall": true, "systemctl": true, "service": true,
	"shutdown": true, "reboot": true, "halt": true, "poweroff": true, "init": true, "telinit": true,
	// Network
	"wget": true, "curl": true, "netcat": true, "nc": true, "nmap": true, "telnet": true,
	"tcpdump": true, "tshark": true, "wireshark": true, "ssh": true, "scp": true, "socat": true,
	// Security/crypto
	"steghide": true, "gpg": true, "openssl": true, "base64": true,
	// Package management
	"apt": true, "apt-get": true, "yum": true, "dnf": true, "rpm": true, "dpkg": true,
	// Editors
	"vi": true, "vim": true, "nano": true, "emacs": true, "ed": true,
	// Shell/execution
	"bash": true, "sh": true, "zsh": true, "ksh": true, "csh": true, "tcsh": true,
	"sudo": true, "su": true, "exec": true, "eval": true,
	// Information gathering
	"grep": true, "egrep": true, "fgrep": true, "find": true, "locate": true,
	"which": true, "whereis": true, "file": true, "stat": true, "ls": true,
	"uname": true, "uptime": true, "who": true, "w": true, "users": true, "id": true,
	"whoami": true, "hostname": true, "dmesg": true, "lsmod": true, "modprobe": true,
	// Persistence/backdoors
	"crontab": true, "at": true, "chattr": true, "lsattr": true,
	// Audit
	"auditctl": true, "ausearch": true, "aureport": true,
	// Monitoring
	"arecord": true, "import": true, "xwd": true,
	// Firewall
	"iptables": true, "ip6tables": true, "firewalld": true, "ufw": true,
	// Development
	"gcc": true, "g++": true, "make": true, "cmake": true, "python": true, "perl": true,
	"ruby": true, "node": true, "java": true,
	// Discovery
	"getcap": true, "chage": true, "passwd": true, "getent": true,
	// Other
	"insmod": true, "rmmod": true, "debugfs": true, "sudoedit": true,
	"echo": true, "printf": true, "read": true,
}

// GuessWazuhField intelligently maps unmapped Sigma field values to Wazuh fields
// Returns the guessed field name or empty string if no good guess
func (m *IntelligentFieldMapper) GuessWazuhField(fieldName string, fieldValue string, sigma *types.SigmaRule) string {
	// Only apply intelligent mapping for Linux auditd
	if strings.ToLower(m.Product) != "linux" {
		return ""
	}

	// Clean the value for analysis
	value := strings.TrimSpace(fieldValue)

	// Remove common regex markers
	value = strings.TrimPrefix(value, "(?i)")  // Remove case-insensitive prefix
	value = strings.TrimPrefix(value, "^")      // Remove start anchor
	value = strings.TrimSuffix(value, "$")      // Remove end anchor

	// Extract first alternative from regex groups like (?:init|telinit) -> init
	// This helps detect commands hidden in regex patterns
	value = extractFirstAlternative(value)

	// Special handling for anonymous fields (empty fieldName from Sigma modifiers like |all)
	// This is common in Linux auditd rules where Sigma doesn't specify exact field names
	if fieldName == "" {
		// Try to guess from value content for process-related events

		// Check for command arguments first (of=, if=, --flag=value)
		if isCommandArgument(value) {
			return "audit.execve.a1"
		}

		// Check for command flags (-s, --flag)
		if isCommandFlag(value) {
			return "audit.execve.a1"
		}

		// Check for file paths (including hidden files like .bash_history)
		if isFilePath(value) {
			return "audit.file.name"
		}

		// Check if it's a known command
		commandName := extractCommandName(value)
		if _, isCommand := commonLinuxCommands[commandName]; isCommand {
			return "audit.execve.a0"
		}

		// If we can't guess, return empty to fall back to full_log
		return ""
	}

	// Category-based guessing for named fields
	category := strings.ToLower(m.Category)

	switch category {
	case "process_creation":
		return m.guessProcessCreationField(fieldName, value)
	case "file_event", "file_access", "file_change":
		return m.guessFileEventField(fieldName, value)
	case "network_connection":
		return m.guessNetworkField(fieldName, value)
	}

	return ""
}

// guessProcessCreationField guesses fields for process creation events
func (m *IntelligentFieldMapper) guessProcessCreationField(fieldName string, value string) string {
	// Check if it's a command flag (starts with -)
	if isCommandFlag(value) {
		// It's likely an argument, but we don't know which position
		// Return a1 as most common first argument
		return "audit.execve.a1"
	}

	// Check if it's a known Linux command
	commandName := extractCommandName(value)
	if _, isCommand := commonLinuxCommands[commandName]; isCommand {
		return "audit.execve.a0"
	}

	// Check if it looks like a path
	if isFilePath(value) {
		return "audit.file.name"
	}

	// Check if it's a number (could be PID, exit code, etc.)
	if isNumeric(value) {
		return "audit.exit"
	}

	return ""
}

// guessFileEventField guesses fields for file events
func (m *IntelligentFieldMapper) guessFileEventField(fieldName string, value string) string {
	if isFilePath(value) {
		// Check if it's a directory pattern
		if strings.HasSuffix(value, "/") || strings.Contains(value, "/*") {
			return "audit.directory.name"
		}
		return "audit.file.name"
	}
	return ""
}

// guessNetworkField guesses fields for network events
func (m *IntelligentFieldMapper) guessNetworkField(fieldName string, value string) string {
	// Check if it's an IP address or hostname
	if isIPAddress(value) || isHostname(value) {
		return "audit.addr"
	}

	// Check if it's a port number
	if isNumeric(value) {
		port := value
		if num := parseNumber(port); num > 0 && num < 65536 {
			return "audit.port"
		}
	}

	return ""
}

// Helper functions

func isCommandFlag(value string) bool {
	// Match patterns like: -s, --flag, -rf, etc.
	matched, _ := regexp.MatchString(`^-+[a-zA-Z0-9]+`, value)
	return matched
}

func isCommandArgument(value string) bool {
	// Match dd/iptables style arguments: if=, of=, --to-ports, etc.
	// Also match key=value patterns
	matched, _ := regexp.MatchString(`^[a-z_]+=|^--[a-z-]+=`, value)
	return matched
}

func extractCommandName(value string) string {
	// Extract command name from path or direct name
	// Examples: /bin/bash -> bash, chmod -> chmod
	parts := strings.Split(value, "/")
	cmdWithArgs := parts[len(parts)-1]

	// Remove any arguments
	cmdParts := strings.Fields(cmdWithArgs)
	if len(cmdParts) > 0 {
		// Remove trailing $ regex anchor
		cmd := strings.TrimSuffix(cmdParts[0], "$")
		return strings.ToLower(cmd)
	}

	return strings.ToLower(value)
}

func isFilePath(value string) bool {
	// Check for common path patterns
	if strings.HasPrefix(value, "/") ||
		strings.HasPrefix(value, "./") ||
		strings.HasPrefix(value, "../") ||
		strings.Contains(value, "/etc/") ||
		strings.Contains(value, "/var/") ||
		strings.Contains(value, "/tmp/") ||
		strings.Contains(value, "/usr/") ||
		strings.Contains(value, "/home/") ||
		strings.Contains(value, "/root/") ||
		strings.Contains(value, "/opt/") ||
		strings.HasPrefix(value, "~") {
		return true
	}

	// Check for hidden files (dotfiles) - common in history tampering
	if strings.HasPrefix(value, ".") {
		// Common history files and config files
		historyFiles := []string{
			".bash_history", ".zsh_history", ".history", ".sh_history",
			".zhistory", ".fish_history", ".mysql_history", ".psql_history",
			".bash_profile", ".bashrc", ".zshrc", ".profile",
		}
		lowerValue := strings.ToLower(value)
		for _, histFile := range historyFiles {
			if strings.Contains(lowerValue, histFile) {
				return true
			}
		}
	}

	// Check for file extensions
	fileExtensions := []string{".log", ".conf", ".config", ".txt", ".sh", ".py", ".pl"}
	for _, ext := range fileExtensions {
		if strings.HasSuffix(value, ext) {
			return true
		}
	}

	return false
}

func isNumeric(value string) bool {
	matched, _ := regexp.MatchString(`^\d+$`, value)
	return matched
}

func extractFirstAlternative(value string) string {
	// Extract first alternative from regex patterns like:
	// (?:init|telinit) -> init
	// (?:execve|execveat) -> execve
	// (?:.bash_history|.zsh_history) -> .bash_history

	// Remove non-capturing group prefix (?:
	if strings.HasPrefix(value, "(?:") {
		value = strings.TrimPrefix(value, "(?:")
		// Remove closing parenthesis
		value = strings.TrimSuffix(value, ")")
	}

	// Take first alternative before pipe |
	if strings.Contains(value, "|") {
		parts := strings.Split(value, "|")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	return value
}

func parseNumber(value string) int {
	var num int
	_, err := fmt.Sscanf(value, "%d", &num)
	if err != nil {
		return 0
	}
	return num
}

func isIPAddress(value string) bool {
	// Simple IP check
	matched, _ := regexp.MatchString(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}`, value)
	return matched
}

func isHostname(value string) bool {
	// Simple hostname pattern
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`, value)
	return matched
}
