// main.go

package main

import (
	"os"
)

func main() {
	if len(os.Args) <= 1 {
		showUsage()
	} else {
		run(os.Args[1:])
	}
}
