package main

import (
	"os"

	"github.com/meinside/balog/cmdline"
)

func main() {
	if len(os.Args) <= 1 {
		cmdline.ShowUsage()
	} else {
		cmdline.ProcessArgs(os.Args[1:])
	}
}
