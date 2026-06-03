package httpapi

import (
	"context"
	"net/http"
	"testing"
)

func TestTransportCoverageHelpers(t *testing.T) {
	if IsUnixTransport(nil) {
		t.Fatal("nil request must not be unix transport")
	}
	req := httptestRequest()
	if IsUnixTransport(req) {
		t.Fatal("plain request must not be unix transport")
	}
	if !IsUnixTransport(req.WithContext(WithUnixTransport(req.Context()))) {
		t.Fatal("unix transport marker was not detected")
	}
	if !AdminOverTCPAllowed() {
		t.Fatal("go test process should allow admin over TCP")
	}
}

func httptestRequest() *http.Request {
	return (&http.Request{}).WithContext(context.Background())
}
