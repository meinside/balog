// util.go

package main

import (
	"fmt"
	"os"
	"strings"
)

// log string to stdout
func l(format string, v ...interface{}) {
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}

	fmt.Printf(format, v...)
}

// log string to stdout, and exit with given exit code
func lexit(exit int, format string, v ...interface{}) {
	l(format, v...)
	os.Exit(exit)
}
