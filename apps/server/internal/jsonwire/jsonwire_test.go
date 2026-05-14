package jsonwire

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("write failed")
}

func TestWriteResponseInjectsSchemaForObjects(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want string
	}{
		{name: "empty object", in: struct{}{}, want: `{"_schema":1}` + "\n"},
		{name: "object", in: map[string]string{"ok": "true"}, want: `{"_schema":1,"ok":"true"}` + "\n"},
		{name: "array", in: []int{1, 2}, want: `[1,2]` + "\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteResponse(&buf, tc.in); err != nil {
				t.Fatalf("write response: %v", err)
			}
			if buf.String() != tc.want {
				t.Fatalf("response = %q, want %q", buf.String(), tc.want)
			}
		})
	}
}

func TestWriteResponsePropagatesMarshalAndWriteFailures(t *testing.T) {
	if err := WriteResponse(&bytes.Buffer{}, make(chan int)); err == nil {
		t.Fatal("expected marshal failure")
	}
	if err := WriteResponse(failingWriter{}, map[string]string{"ok": "true"}); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected object write failure, got %v", err)
	}
	if err := WriteResponse(&failOnWriteNumber{failOn: 2}, map[string]string{"ok": "true"}); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected object body write failure, got %v", err)
	}
	if err := WriteResponse(&failOnWriteNumber{failOn: 1}, struct{}{}); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected empty object write failure, got %v", err)
	}
	if err := WriteResponse(failingWriter{}, []int{1}); err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("expected scalar write failure, got %v", err)
	}
}

type failOnWriteNumber struct {
	count  int
	failOn int
}

func (w *failOnWriteNumber) Write([]byte) (int, error) {
	w.count++
	if w.count == w.failOn {
		return 0, errors.New("write failed")
	}
	return 1, nil
}
