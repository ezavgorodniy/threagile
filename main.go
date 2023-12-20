package main

import (
	"github.com/threagile/threagile/pkg"
)

const (
	buildTimestamp = ""
)

// === Error handling stuff ========================================

func main() {

	// TODO: uncomment below as soon as refactoring is finished - everything will go through rootCmd.Execute
	// cmd.Execute()

	// TODO: remove below as soon as refactoring is finished - everything will go through rootCmd.Execute
	// for now it's fine to have as frequently uncommented to see the actual behaviour
	context := new(pkg.Context).Defaults(buildTimestamp)
	context.ParseCommandlineArgs()
	if context.ServerMode {
		context.StartServer()
	} else {
		context.DoIt()
	}
}
