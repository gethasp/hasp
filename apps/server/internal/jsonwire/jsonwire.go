package jsonwire

import (
	"encoding/json"
	"fmt"
	"io"
)

// SchemaVersion is the top-level `_schema` field stamped on JSON object
// responses so consumers can detect breaking shape changes.
const SchemaVersion = 1

// WriteResponse marshals payload as JSON, injecting the top-level `_schema`
// field when the result is a JSON object. Slice/array or scalar payloads are
// written as-is so the helper stays a drop-in replacement for
// json.NewEncoder(...).Encode(...).
func WriteResponse(w io.Writer, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if len(data) > 0 && data[0] == '{' {
		if len(data) == 2 {
			if _, err := fmt.Fprintf(w, `{"_schema":%d}`, SchemaVersion); err != nil {
				return err
			}
		} else {
			if _, err := fmt.Fprintf(w, `{"_schema":%d,`, SchemaVersion); err != nil {
				return err
			}
			if _, err := w.Write(data[1:]); err != nil {
				return err
			}
		}
	} else {
		if _, err := w.Write(data); err != nil {
			return err
		}
	}
	_, err = fmt.Fprintln(w)
	return err
}
