// Package envmap validates child environment destinations and literal values.
package envmap

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate rejects ambiguous destinations before authorization consumes grants.
func Validate(env, files, literals map[string]string) error {
	seen := map[string]string{}
	for _, channel := range []struct {
		name   string
		values map[string]string
	}{{"env", env}, {"files", files}, {"literal_env", literals}} {
		for _, name := range Names(channel.values) {
			value := channel.values[name]
			if !namePattern.MatchString(name) {
				return fmt.Errorf("invalid environment name %q in %s", name, channel.name)
			}
			if previous, ok := seen[name]; ok {
				return fmt.Errorf("environment destination %q appears in both %s and %s", name, previous, channel.name)
			}
			seen[name] = channel.name
			if strings.ContainsRune(value, '\x00') {
				return fmt.Errorf("%s value for %q contains NUL", channel.name, name)
			}
			if channel.name == "literal_env" {
				if strings.HasPrefix(strings.ToUpper(name), "HASP_") {
					return fmt.Errorf("literal_env destination %q is reserved for HASP", name)
				}
			} else if strings.TrimSpace(value) == "" {
				return fmt.Errorf("%s reference for %q is empty; use --literal-env (MCP literal_env) for configuration values", channel.name, name)
			}
		}
	}
	return nil
}

func Names(values map[string]string) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// LiteralFlag preserves every byte after the first equals sign, including empty values.
type LiteralFlag map[string]string

func (f *LiteralFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(Names(*f), ",")
}
func (f *LiteralFlag) Set(raw string) error {
	name, value, ok := strings.Cut(raw, "=")
	if !ok {
		return fmt.Errorf("expected NAME=VALUE")
	}
	if err := Validate(nil, nil, map[string]string{name: value}); err != nil {
		return err
	}
	if *f == nil {
		*f = map[string]string{}
	}
	if _, exists := (*f)[name]; exists {
		return fmt.Errorf("duplicate literal_env destination %q", name)
	}
	(*f)[name] = value
	return nil
}
