package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

// appError is the structured-error envelope emitted on stderr when a
// command runs with --json and fails. It implements error so it can be
// returned through the normal command surface and unwrapped at the
// process boundary.
type appError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

func newAppError(code string, message string) *appError {
	return &appError{Code: code, Message: message}
}

func (e *appError) Error() string {
	return e.Message
}

func (e *appError) withHint(hint string) *appError {
	e.Hint = hint
	return e
}

func (e *appError) jsonBytes() []byte {
	envelope := map[string]*appError{"error": e}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	_ = enc.Encode(envelope)
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// WriteCLIError is the exported binary-boundary entry point for writeCLIError.
func WriteCLIError(stderr io.Writer, err error, jsonMode bool) {
	writeCLIError(stderr, err, jsonMode)
}

// ArgsRequestJSON is the exported binary-boundary entry point for argsRequestJSON.
func ArgsRequestJSON(args []string) bool {
	return argsRequestJSON(args)
}

// writeCLIError serialises err to stderr. When jsonMode is true the output is
// a single JSON envelope of the form {"error":{"code":"…","message":"…"}};
// otherwise a plain-text line is written.
func writeCLIError(stderr io.Writer, err error, jsonMode bool) {
	if stderr == nil || err == nil {
		return
	}
	if !jsonMode {
		fmt.Fprintln(stderr, err.Error())
		return
	}
	envelope, ok := err.(*appError)
	if !ok {
		envelope = newAppError("internal_error", err.Error())
	}
	stderr.Write(envelope.jsonBytes())
	stderr.Write([]byte("\n"))
}

// assertSingleJSONDocument reports an error if the byte slice does not
// contain exactly one JSON document (followed only by trailing whitespace).
// Used by the --json contract harness to catch commands that emit human
// noise alongside the JSON payload.
func assertSingleJSONDocument(out []byte) error {
	dec := json.NewDecoder(bytes.NewReader(out))
	var first json.RawMessage
	if err := dec.Decode(&first); err != nil {
		return fmt.Errorf("first decode: %w", err)
	}
	if dec.More() {
		var rest json.RawMessage
		_ = dec.Decode(&rest)
		return fmt.Errorf("expected exactly one JSON document, got more (next=%s)", rest)
	}
	tail := bytes.TrimSpace(out[dec.InputOffset():])
	if len(tail) > 0 {
		return fmt.Errorf("trailing non-whitespace after JSON document: %q", tail)
	}
	return nil
}

// argsRequestJSON returns true when the argument list contains a --json or
// -json switch (with or without =true). Used at the process boundary to
// pick the error encoding before dispatch resolves.
func argsRequestJSON(args []string) bool {
	for _, arg := range args {
		switch arg {
		case "--json", "-json", "--json=true", "-json=true":
			return true
		}
	}
	return false
}
