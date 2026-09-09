package envmap

import (
	"reflect"
	"strings"
	"testing"
)

func TestValidateRejectsAmbiguousAndInvalidDestinations(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		env, files, literals map[string]string
		want                 string
	}{
		{name: "invalid name", env: map[string]string{"BAD NAME": "@TOKEN"}, want: "invalid environment name"},
		{name: "collision", env: map[string]string{"TOKEN": "@ONE"}, files: map[string]string{"TOKEN": "@TWO"}, want: "both env and files"},
		{name: "NUL", literals: map[string]string{"TEXT": "a\x00b"}, want: "contains NUL"},
		{name: "reserved", literals: map[string]string{"hasp_session_token": "value"}, want: "reserved"},
		{name: "empty reference", files: map[string]string{"FILE": " "}, want: "reference for \"FILE\" is empty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.env, tc.files, tc.literals); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validation: %v", err)
			}
		})
	}
	if err := Validate(map[string]string{"TOKEN": "@ONE"}, map[string]string{"TOKEN_FILE": "@TWO"}, map[string]string{"CI": "1", "EMPTY": ""}); err != nil {
		t.Fatal(err)
	}
}

func TestLiteralFlagPreservesValuesAndHidesThemFromString(t *testing.T) {
	var absent *LiteralFlag
	if absent.String() != "" {
		t.Fatal("nil flag has text")
	}
	var flag LiteralFlag
	for _, raw := range []string{"EXACT=  @TOKEN=$HOME=a=b ", "EMPTY="} {
		if err := flag.Set(raw); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(flag, LiteralFlag{"EXACT": "  @TOKEN=$HOME=a=b ", "EMPTY": ""}) || flag.String() != "EMPTY,EXACT" {
		t.Fatalf("literal flag: %#v; display %s", flag, flag.String())
	}
	for _, raw := range []string{"MISSING_EQUALS", "BAD NAME=x", "EMPTY=overwritten"} {
		if err := flag.Set(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	if flag["EMPTY"] != "" {
		t.Fatal("duplicate replaced original value")
	}
}
