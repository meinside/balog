package util

import (
	"fmt"
	"os"
	"strings"
)

// Log prints string to stdout
func Log(format string, v ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}

	fmt.Printf(format, v...)
}

// LogAndExit prints string to stdout, and exit with given exit code
func LogAndExit(exit int, format string, v ...interface{}) {
	Log(format, v...)
	os.Exit(exit)
}
