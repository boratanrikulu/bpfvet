package main

import (
	"os"

	"github.com/boratanrikulu/bpfvet/cmd/bpfvet/app"
)

func main() {
	if err := app.Execute(); err != nil {
		os.Exit(1)
	}
}
