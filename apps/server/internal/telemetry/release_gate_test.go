package telemetry

import (
	"encoding/json"
	"runtime"
	"testing"
)

func TestReleaseGatePayloadUsesCurrentEncoderContract(t *testing.T) {
	body, err := ReleaseGatePayload()
	if err != nil {
		t.Fatalf("release gate payload: %v", err)
	}
	var payload Payload
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("decode release gate payload: %v", err)
	}
	if err := ValidatePayload(payload); err != nil {
		t.Fatalf("release gate payload validation: %v", err)
	}
	if payload.SchemaVersion != SchemaVersion ||
		payload.InstallIDHash != "0000000000000000000000000000000000000000000000000000000000000000" ||
		payload.HaspVersion != releaseGateVersion ||
		payload.OS != runtime.GOOS ||
		payload.Arch != runtime.GOARCH ||
		payload.InstallMethod != "unknown" ||
		payload.PeriodHours != defaultPeriodHours {
		t.Fatalf("unexpected release gate payload: %+v", payload)
	}
}
