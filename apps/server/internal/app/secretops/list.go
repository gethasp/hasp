package secretops

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/app/secrettypes"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func secretListCommand(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := newFlagSet(deps, "secret list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	items := deps.ListItems(handle)
	secrets := make([]secrettypes.MetadataView, 0, len(items))
	for _, item := range items {
		secrets = append(secrets, secrettypes.MetadataView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			CreatedAt:      item.CreatedAt.Format(secrettypes.TimeRFC3339),
			UpdatedAt:      item.UpdatedAt.Format(secrettypes.TimeRFC3339),
			Exposures:      deps.ItemExposures(handle, item.Name),
		})
	}
	opts := deps.GlobalFlagsColorOptions(ctx, stdout)
	return deps.RenderSecretListJSONOrHumanWithColor(ctx, stdout, *jsonOutput, secrets, opts)
}

// secretSearchCommand filters the vault inventory by a case-insensitive
// substring match on the item name.
func secretSearchCommand(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := newFlagSet(deps, "secret search", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp secret search <substr> [--json]")
	}
	query := strings.ToLower(strings.TrimSpace(fs.Arg(0)))
	if query == "" {
		return errors.New("usage: hasp secret search <substr> [--json]")
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	items := deps.ListItems(handle)
	total := len(items)
	secrets := make([]secrettypes.MetadataView, 0, len(items))
	for _, item := range items {
		if !strings.Contains(strings.ToLower(item.Name), query) {
			continue
		}
		secrets = append(secrets, secrettypes.MetadataView{
			Name:           item.Name,
			NamedReference: store.NamedReference(item.Name),
			Kind:           item.Kind,
			CreatedAt:      item.CreatedAt.Format(secrettypes.TimeRFC3339),
			UpdatedAt:      item.UpdatedAt.Format(secrettypes.TimeRFC3339),
			Exposures:      deps.ItemExposures(handle, item.Name),
		})
	}
	opts := deps.GlobalFlagsColorOptions(ctx, stdout)
	return deps.RenderSecretSearchJSONOrHuman(ctx, stdout, *jsonOutput, fs.Arg(0), total, secrets, opts)
}

// secretDiffCommand compares a candidate .env file against the vault.
func secretDiffCommand(ctx context.Context, deps Deps, args []string, stdout io.Writer) error {
	fs := newFlagSet(deps, "secret diff", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	jsonOutput := fs.Bool("json", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: hasp secret diff <path> [--json]")
	}
	path := strings.TrimSpace(fs.Arg(0))
	if path == "" {
		return errors.New("usage: hasp secret diff <path> [--json]")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	candidate, err := parseDotEnvForDiff(bytes.NewReader(data))
	if err != nil {
		return err
	}
	handle, err := deps.OpenVault(ctx)
	if err != nil {
		return err
	}
	vault := map[string]string{}
	for _, item := range deps.ListItems(handle) {
		if item.Kind != store.ItemKindKV {
			continue
		}
		full, err := deps.GetItem(handle, item.Name)
		if err != nil {
			return err
		}
		vault[item.Name] = string(full.Value)
	}
	same := []string{}
	changed := []string{}
	missing := []string{}
	extra := []string{}
	for name, vaultValue := range vault {
		candidateValue, ok := candidate[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if candidateValue == vaultValue {
			same = append(same, name)
		} else {
			changed = append(changed, name)
		}
	}
	for name := range candidate {
		if _, ok := vault[name]; !ok {
			extra = append(extra, name)
		}
	}
	sort.Strings(same)
	sort.Strings(changed)
	sort.Strings(missing)
	sort.Strings(extra)
	payload := map[string]any{
		"same":    same,
		"changed": changed,
		"missing": missing,
		"extra":   extra,
	}
	return deps.RenderJSONOrHuman(ctx, stdout, *jsonOutput, payload, func(w io.Writer) error {
		return renderSecretDiff(w, path, same, changed, missing, extra)
	})
}

// parseDotEnvForDiff extracts name→value pairs from a .env reader.
func parseDotEnvForDiff(reader io.Reader) (map[string]string, error) {
	out := map[string]string{}
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
		}
		out[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan env file: %w", err)
	}
	return out, nil
}

func renderSecretDiff(w io.Writer, path string, same, changed, missing, extra []string) error {
	if _, err := fmt.Fprintf(w, "Secret diff vs %s\n", path); err != nil {
		return err
	}
	for _, bucket := range []struct {
		label string
		names []string
	}{
		{"same", same},
		{"changed", changed},
		{"missing", missing},
		{"extra", extra},
	} {
		joined := strings.Join(bucket.names, ", ")
		if _, err := fmt.Fprintf(w, "  %-7s (%d): %s\n", bucket.label, len(bucket.names), joined); err != nil {
			return err
		}
	}
	return nil
}
