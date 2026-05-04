package store

import (
	"errors"
	"strings"
	"testing"
)

type dotenvErrorReader struct{}

func (dotenvErrorReader) Read([]byte) (int, error) {
	return 0, errors.New("read")
}

func TestParseDotEnvHandlesSharedImportAndDiffGrammar(t *testing.T) {
	got, err := ParseDotEnvMap(strings.NewReader("\n# comment\nexport A=\"quoted\\\"\"\nB=plain'\nC='single quoted'\n"))
	if err != nil {
		t.Fatalf("parse dotenv: %v", err)
	}
	if got["A"] != "quoted\"" || got["B"] != "plain'" || got["C"] != "single quoted" {
		t.Fatalf("unexpected parsed dotenv values: %v", got)
	}
	if _, err := ParseDotEnv(strings.NewReader("NOPE\n")); err == nil {
		t.Fatal("expected invalid env line error")
	}
	if _, err := ParseDotEnvMap(strings.NewReader("NOPE\n")); err == nil {
		t.Fatal("expected invalid env line error through map parser")
	}
	if _, err := ParseDotEnv(dotenvErrorReader{}); err == nil {
		t.Fatal("expected scanner error")
	}
}
