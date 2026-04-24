package store

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type ImportOptions struct {
	ProjectRoot   string
	BindToProject bool
	Name          string
}

type ImportResult struct {
	Imported []ImportedItem `json:"imported"`
}

type ImportedItem struct {
	Name  string   `json:"name"`
	Kind  ItemKind `json:"kind"`
	Alias string   `json:"alias,omitempty"`
}

var (
	ErrReferenceNotFound  = errors.New("reference not found")
	ErrReferenceAmbiguous = errors.New("reference is ambiguous")
)

type ResolvedReference struct {
	Reference      string   `json:"reference"`
	Alias          string   `json:"alias,omitempty"`
	NamedReference string   `json:"named_reference,omitempty"`
	ItemName       string   `json:"item_name"`
	ItemKind       ItemKind `json:"item_kind"`
}

const namedReferencePrefix = "@"

func NamedReference(itemName string) string {
	trimmed := strings.TrimSpace(itemName)
	if trimmed == "" {
		return ""
	}
	return namedReferencePrefix + trimmed
}

func parseNamedReference(reference string) (string, bool) {
	ref := strings.TrimSpace(reference)
	if !strings.HasPrefix(ref, namedReferencePrefix) {
		return "", false
	}
	return strings.TrimSpace(strings.TrimPrefix(ref, namedReferencePrefix)), true
}

func bindingAliasForItem(binding Binding, itemName string) string {
	match := ""
	for alias, existing := range binding.Aliases {
		if existing != itemName {
			continue
		}
		if match == "" || strings.Compare(alias, match) < 0 {
			match = alias
		}
	}
	return match
}

func (h *Handle) ImportPath(ctx context.Context, path string, opts ImportOptions) (ImportResult, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".env":
		return h.importEnvFile(ctx, path, opts)
	case ".json":
		return h.importJSONFile(ctx, path, opts)
	default:
		return ImportResult{}, fmt.Errorf("unsupported import format for %s", path)
	}
}

func (h *Handle) ImportEnvFile(path string) ([]Item, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open env file: %w", err)
	}
	defer file.Close()

	items := make([]Item, 0)
	scanner := bufio.NewScanner(file)
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
		}
		value = strings.Trim(value, `"'`)
		item, err := h.UpsertItem(key, ItemKindKV, []byte(value), ItemMetadata{})
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan env file: %w", err)
	}
	return items, nil
}

func (h *Handle) importEnvFile(ctx context.Context, path string, opts ImportOptions) (ImportResult, error) {
	items, err := h.ImportEnvFile(path)
	if err != nil {
		return ImportResult{}, err
	}
	result := ImportResult{Imported: make([]ImportedItem, 0, len(items))}
	for _, item := range items {
		imported := ImportedItem{Name: item.Name, Kind: item.Kind}
		if opts.BindToProject {
			alias, err := h.BindItemAlias(ctx, opts.ProjectRoot, item.Name)
			if err != nil {
				return ImportResult{}, err
			}
			imported.Alias = alias
		}
		result.Imported = append(result.Imported, imported)
	}
	return result, nil
}

func (h *Handle) ImportJSONCredential(path string, name string) (Item, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Item{}, fmt.Errorf("read json credential: %w", err)
	}
	var payload any
	if err := json.Unmarshal(data, &payload); err != nil {
		return Item{}, fmt.Errorf("decode json credential: %w", err)
	}
	if strings.TrimSpace(name) == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return h.UpsertItem(name, ItemKindFile, data, ItemMetadata{
		Tags: []string{"json"},
	})
}

func (h *Handle) importJSONFile(ctx context.Context, path string, opts ImportOptions) (ImportResult, error) {
	item, err := h.ImportJSONCredential(path, opts.Name)
	if err != nil {
		return ImportResult{}, err
	}
	imported := ImportedItem{Name: item.Name, Kind: item.Kind}
	if opts.BindToProject {
		alias, err := h.BindItemAlias(ctx, opts.ProjectRoot, item.Name)
		if err != nil {
			return ImportResult{}, err
		}
		imported.Alias = alias
	}
	return ImportResult{Imported: []ImportedItem{imported}}, nil
}

func (h *Handle) ResolveReference(ctx context.Context, projectPath string, reference string) (ResolvedReference, error) {
	binding, err := h.resolvedBinding(ctx, projectPath)
	if err != nil {
		return ResolvedReference{}, err
	}

	ref := strings.TrimSpace(reference)
	if ref == "" {
		return ResolvedReference{}, ErrReferenceNotFound
	}

	aliasItemName, aliasFound := binding.Aliases[ref]
	if aliasFound {
		item, err := h.GetItem(aliasItemName)
		if err != nil {
			return ResolvedReference{}, err
		}
		return ResolvedReference{
			Reference:      ref,
			Alias:          ref,
			NamedReference: NamedReference(item.Name),
			ItemName:       item.Name,
			ItemKind:       item.Kind,
		}, nil
	}
	if itemName, ok := parseNamedReference(ref); ok {
		if itemName == "" {
			return ResolvedReference{}, ErrReferenceNotFound
		}
		alias := bindingAliasForItem(binding, itemName)
		if alias == "" {
			return ResolvedReference{}, fmt.Errorf("%w: %q", ErrReferenceNotFound, ref)
		}
		item, err := h.GetItem(itemName)
		if err != nil {
			return ResolvedReference{}, err
		}
		return ResolvedReference{
			Reference:      ref,
			Alias:          alias,
			NamedReference: NamedReference(item.Name),
			ItemName:       item.Name,
			ItemKind:       item.Kind,
		}, nil
	}
	return ResolvedReference{}, fmt.Errorf("%w: %q", ErrReferenceNotFound, ref)
}

func (h *Handle) ResolveReferences(ctx context.Context, projectPath string, references []string) ([]ResolvedReference, error) {
	out := make([]ResolvedReference, 0, len(references))
	for _, reference := range references {
		resolved, err := h.ResolveReference(ctx, projectPath, reference)
		if err != nil {
			return nil, err
		}
		out = append(out, resolved)
	}
	return out, nil
}

func (h *Handle) ResolveReferenceItem(ctx context.Context, projectPath string, reference string) (Item, error) {
	resolved, err := h.ResolveReference(ctx, projectPath, reference)
	if err != nil {
		return Item{}, err
	}
	return h.GetItem(resolved.ItemName)
}
