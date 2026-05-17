package main

import (
	"fmt"
	"io"
	"os"

	"github.com/gethasp/hasp/apps/server/internal/telemetry"
)

var (
	exitFn               = os.Exit
	releaseGatePayloadFn = telemetry.ReleaseGatePayload
)

func main() {
	if code := run(os.Args[1:], os.Stdout, os.Stderr); code != 0 {
		exitFn(code)
	}
}

func run(args []string, stdout io.Writer, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--endpoint" {
		fmt.Fprintln(stdout, telemetry.TrustedEndpoint)
		return 0
	}
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: telemetry-release-payload [--endpoint]")
		return 2
	}

	body, err := releaseGatePayloadFn()
	if err != nil {
		fmt.Fprintf(stderr, "build telemetry release payload: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(body)
	_, _ = stdout.Write([]byte("\n"))
	return 0
}
