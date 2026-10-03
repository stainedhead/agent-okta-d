// Command agent-okta-d is the credential daemon and its operator CLI. All
// behavior lives in internal/app; this file only supplies the production
// environment and the process signals.
package main

import (
	"os"

	"github.com/stainedhead/agent-okta-d/internal/app"
)

func main() {
	sigs, stop := app.NotifySignals()
	code := app.Main(os.Args[1:], app.DefaultEnv(), sigs)
	stop()
	os.Exit(code)
}
