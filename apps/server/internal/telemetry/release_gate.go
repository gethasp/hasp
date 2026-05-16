package telemetry

import (
	"runtime"
	"strings"
)

const releaseGateVersion = "release-gate"

// ReleaseGatePayload returns the minimal telemetry ping body used by release
// verification to prove the trusted endpoint accepts the current CLI payload
// contract. It intentionally routes through EncodePayload so release checks fail
// if the CLI encoder and endpoint contract drift apart.
func ReleaseGatePayload() ([]byte, error) {
	return EncodePayload(Payload{
		SchemaVersion: SchemaVersion,
		InstallIDHash: strings.Repeat("0", 64),
		HaspVersion:   releaseGateVersion,
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		InstallMethod: "unknown",
		PeriodHours:   defaultPeriodHours,
		TopCommands:   []CommandCount{},
		Setup:         Counts{},
		Features:      Counts{},
		Safety:        Counts{},
		Errors:        Counts{},
		Performance:   Counts{},
	})
}
