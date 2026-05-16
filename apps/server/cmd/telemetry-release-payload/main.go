package main

import (
	"fmt"
	"os"

	"github.com/gethasp/hasp/apps/server/internal/telemetry"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--endpoint" {
		fmt.Println(telemetry.TrustedEndpoint)
		return
	}
	if len(os.Args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: telemetry-release-payload [--endpoint]")
		os.Exit(2)
	}

	body, err := telemetry.ReleaseGatePayload()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build telemetry release payload: %v\n", err)
		os.Exit(1)
	}
	_, _ = os.Stdout.Write(body)
	_, _ = os.Stdout.Write([]byte("\n"))
}
