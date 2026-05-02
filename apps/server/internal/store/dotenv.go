package store

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"
)

type DotEnvEntry struct {
	Key   string
	Value string
}

func ParseDotEnv(reader io.Reader) ([]DotEnvEntry, error) {
	entries := []DotEnvEntry{}
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("invalid env line %q", line)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		} else if len(value) >= 2 && value[0] == '\'' && value[len(value)-1] == '\'' {
			value = value[1 : len(value)-1]
		}
		entries = append(entries, DotEnvEntry{Key: key, Value: value})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan env file: %w", err)
	}
	return entries, nil
}

func ParseDotEnvMap(reader io.Reader) (map[string]string, error) {
	entries, err := ParseDotEnv(reader)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, entry := range entries {
		out[entry.Key] = entry.Value
	}
	return out, nil
}
