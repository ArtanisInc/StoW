package utils

import (
	"fmt"
	"log"
	"runtime"
	"strings"
)

// Log levels
const (
	DEBUG = "debug"
	INFO  = "info"
	WARN  = "warn"
	ERROR = "error"
)

// LogIt logs a message with the specified level
func LogIt(level string, msg string, err error, showInfo bool, showDebug bool) {
	// Skip debug logs if not enabled
	if level == DEBUG && !showDebug {
		return
	}

	// Skip info logs if not enabled
	if level == INFO && !showInfo {
		return
	}

	// Build log message
	var logMsg string
	if msg != "" {
		logMsg = msg
	}

	if err != nil {
		if logMsg != "" {
			logMsg += ": " + err.Error()
		} else {
			logMsg = err.Error()
		}
	}

	// Add caller info for debug
	if level == DEBUG {
		pc, _, _, ok := runtime.Caller(1)
		if ok {
			funcName := runtime.FuncForPC(pc).Name()
			parts := strings.Split(funcName, "/")
			funcName = parts[len(parts)-1]
			logMsg = fmt.Sprintf("[%s] %s", funcName, logMsg)
		}
	}

	// Log with prefix
	prefix := strings.ToUpper(level)
	if logMsg != "" {
		log.Printf("[%s] %s", prefix, logMsg)
	}

	// Fatal on error
	if level == ERROR && err != nil {
		log.Fatalf("[FATAL] %s", logMsg)
	}
}
