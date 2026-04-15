package app

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/store"
)

var createTempImportFn = os.CreateTemp
var writeImportFileFn = os.WriteFile

type importPlanItem struct {
	Name  string         `json:"name"`
	Kind  store.ItemKind `json:"kind"`
	Alias string         `json:"alias,omitempty"`
}

type importPreview struct {
	Source           string           `json:"source"`
	Format           string           `json:"format"`
	CaptureModeLabel string           `json:"capture_mode_label"`
	LocalHygienePath bool             `json:"local_hygiene_path"`
	BindToProject    bool             `json:"bind_to_project"`
	PlannedChanges   []importPlanItem `json:"planned_changes"`
	Notes            []string         `json:"notes"`
}

type preparedImport struct {
	Preview        importPreview
	Path           string
	ProjectedNames []string
	cleanup        func()
}

func (p preparedImport) Cleanup() {
	if p.cleanup != nil {
		p.cleanup()
	}
}

func prepareImport(path string, format string, name string, stdin io.Reader, bindToProject bool, existingAliases map[string]string) (preparedImport, error) {
	if strings.TrimSpace(path) == "" {
		return preparedImport{}, errors.New("import path is required")
	}
	data, source, resolvedFormat, actualPath, cleanup, err := importBytes(path, format, stdin)
	if err != nil {
		return preparedImport{}, err
	}
	items, err := previewImportItems(source, resolvedFormat, name, data, bindToProject, existingAliases)
	if err != nil {
		if cleanup != nil {
			cleanup()
		}
		return preparedImport{}, err
	}
	notes := []string{
		"local import is an explicit human CLI capture path and remains separate from the agent-safe broker path",
	}
	if source == "stdin" {
		notes = append(notes, "stdin import is intended for pasted values or shell-export snippets without creating repo-visible env files")
	}
	if bindToProject {
		notes = append(notes, "planned aliases are previewed before import writes local state")
	}
	return preparedImport{
		Preview: importPreview{
			Source:           source,
			Format:           resolvedFormat,
			CaptureModeLabel: map[bool]string{true: "local-import-stdin", false: "local-import-file"}[source == "stdin"],
			LocalHygienePath: source == "stdin",
			BindToProject:    bindToProject,
			PlannedChanges:   items,
			Notes:            notes,
		},
		Path:           actualPath,
		ProjectedNames: projectedNames(items),
		cleanup:        cleanup,
	}, nil
}

func importBytes(path string, format string, stdin io.Reader) ([]byte, string, string, string, func(), error) {
	source := strings.TrimSpace(path)
	if source == "-" {
		if stdin == nil {
			return nil, "", "", "", nil, errors.New("stdin import requested but no stdin reader was provided")
		}
		data, err := io.ReadAll(stdin)
		if err != nil {
			return nil, "", "", "", nil, err
		}
		resolvedFormat, err := resolveImportFormat(path, format)
		if err != nil {
			return nil, "", "", "", nil, err
		}
		tempFile, err := createTempImportFn("", "hasp-import-*."+resolvedFormat)
		if err != nil {
			return nil, "", "", "", nil, err
		}
		if err := tempFile.Close(); err != nil {
			_ = os.Remove(tempFile.Name())
			return nil, "", "", "", nil, err
		}
		if err := writeImportFileFn(tempFile.Name(), data, 0o600); err != nil {
			_ = os.Remove(tempFile.Name())
			return nil, "", "", "", nil, err
		}
		return data, "stdin", resolvedFormat, tempFile.Name(), func() { _ = os.Remove(tempFile.Name()) }, nil
	}
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, "", "", "", nil, err
	}
	resolvedFormat, err := resolveImportFormat(source, format)
	if err != nil {
		return nil, "", "", "", nil, err
	}
	return data, source, resolvedFormat, source, nil, nil
}

func resolveImportFormat(path string, format string) (string, error) {
	switch strings.TrimSpace(format) {
	case "", "auto":
		switch strings.ToLower(filepath.Ext(path)) {
		case ".env":
			return "env", nil
		case ".json":
			return "json", nil
		case "":
			if path == "-" {
				return "env", nil
			}
		}
		return "", fmt.Errorf("unsupported import format for %s", path)
	case "env", "json":
		return format, nil
	default:
		return "", fmt.Errorf("unsupported import format %q", format)
	}
}

func previewImportItems(source string, format string, name string, data []byte, bindToProject bool, existingAliases map[string]string) ([]importPlanItem, error) {
	switch format {
	case "env":
		return previewEnvImportItems(data, bindToProject, existingAliases)
	case "json":
		return previewJSONImportItem(source, name, bindToProject, existingAliases)
	default:
		return nil, fmt.Errorf("unsupported import format %q", format)
	}
}

func previewEnvImportItems(data []byte, bindToProject bool, existingAliases map[string]string) ([]importPlanItem, error) {
	return previewEnvImportReader(bytes.NewReader(data), bindToProject, existingAliases)
}

func previewEnvImportReader(reader io.Reader, bindToProject bool, existingAliases map[string]string) ([]importPlanItem, error) {
	aliases := cloneAliasSet(existingAliases)
	items := []importPlanItem{}
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
		_, _ = strconv.Unquote(value)
		item := importPlanItem{Name: key, Kind: store.ItemKindKV}
		if bindToProject {
			item.Alias = projectAlias(item.Kind, key, aliases)
		}
		items = append(items, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan env import: %w", err)
	}
	return items, nil
}

func previewJSONImportItem(source string, name string, bindToProject bool, existingAliases map[string]string) ([]importPlanItem, error) {
	itemName := strings.TrimSpace(name)
	if itemName == "" {
		base := filepath.Base(source)
		if source == "stdin" {
			base = "stdin"
		}
		itemName = strings.TrimSuffix(base, filepath.Ext(base))
	}
	item := importPlanItem{Name: itemName, Kind: store.ItemKindFile}
	if bindToProject {
		item.Alias = projectAlias(item.Kind, itemName, cloneAliasSet(existingAliases))
	}
	return []importPlanItem{item}, nil
}

func projectAlias(kind store.ItemKind, itemName string, aliases map[string]string) string {
	for alias, existing := range aliases {
		if existing == itemName {
			return alias
		}
	}
	alias := store.GenerateNeutralAlias(kind, aliases)
	aliases[alias] = itemName
	return alias
}

func cloneAliasSet(in map[string]string) map[string]string {
	out := map[string]string{}
	for key, value := range in {
		out[key] = value
	}
	return out
}

func projectedNames(items []importPlanItem) []string {
	names := make([]string, 0, len(items))
	for _, item := range items {
		names = append(names, item.Name)
	}
	return names
}

func encodeImportCommandResult(stdout io.Writer, preview importPreview, result *store.ImportResult, applied bool) error {
	payload := map[string]any{
		"preview": preview,
		"applied": applied,
	}
	if result != nil {
		payload["imported"] = result.Imported
	}
	return json.NewEncoder(stdout).Encode(payload)
}
