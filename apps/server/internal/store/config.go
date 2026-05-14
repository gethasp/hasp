package store

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var (
	ErrConfigKeyNotFound = errors.New("config key not found")
	ErrConfigInvalid     = errors.New("config invalid")
)

var configIntBounds = func() (int64, int64) {
	maxInt := int64(int(^uint(0) >> 1))
	return -maxInt - 1, maxInt
}

type ConfigDocument map[string]any

type ConfigValue struct {
	Value any `json:"value"`
}

type configSpec struct {
	defaultValue any
	validate     func(any) (any, error)
}

var configSpecs = map[string]configSpec{
	"vault.idle_relock_s":                      {defaultValue: 600, validate: validateIntRange("vault.idle_relock_s", 30, 86400)},
	"vault.auto_relock_enabled":                {defaultValue: true, validate: validateBool("vault.auto_relock_enabled")},
	"vault.biometric_unlock_enabled":           {defaultValue: true, validate: validateBool("vault.biometric_unlock_enabled")},
	"audit.retention_days":                     {defaultValue: 90, validate: validateIntRange("audit.retention_days", 1, 3650)},
	"audit.export_format_default":              {defaultValue: "ndjson", validate: validateEnum("audit.export_format_default", []string{"ndjson"})},
	"reveal.scrub_seconds":                     {defaultValue: 30, validate: validateIntRange("reveal.scrub_seconds", 5, 3600)},
	"clipboard.scrub_seconds":                  {defaultValue: 60, validate: validateIntRange("clipboard.scrub_seconds", 5, 3600)},
	"notifications.approvals_enabled":          {defaultValue: true, validate: validateBool("notifications.approvals_enabled")},
	"notifications.expiring_lease_threshold_s": {defaultValue: 1800, validate: validateIntRange("notifications.expiring_lease_threshold_s", 60, 86400)},
	"notifications.critical_consumer_ids":      {defaultValue: []string{}, validate: validateAnyStringSlice("notifications.critical_consumer_ids")},
	"ui.language":                              {defaultValue: "system", validate: validateEnum("ui.language", []string{"system", "en"})},
	"ui.reduce_motion_override":                {defaultValue: "system", validate: validateEnum("ui.reduce_motion_override", []string{"system", "on", "off"})},
	"ui.differentiate_without_color":           {defaultValue: false, validate: validateBool("ui.differentiate_without_color")},
	"updates.channel":                          {defaultValue: "stable", validate: validateEnum("updates.channel", []string{"stable", "beta"})},
	"integrations.disabled_targets":            {defaultValue: []string{}, validate: validateStringSlice("integrations.disabled_targets", []string{"env-injection", "mcp", "shell-hook"})},
	"backup.schedule":                          {defaultValue: "off", validate: validateEnum("backup.schedule", []string{"off", "daily", "weekly"})},
	"backup.retention_count":                   {defaultValue: 5, validate: validateIntRange("backup.retention_count", 1, 90)},
	"backup.destination_path":                  {defaultValue: "", validate: validateString("backup.destination_path", 4096)},
	"backup.last_backup_at":                    {defaultValue: "", validate: validateString("backup.last_backup_at", 128)},
	"backup.last_backup_path":                  {defaultValue: "", validate: validateString("backup.last_backup_path", 4096)},
}

func (h *Handle) GetConfig() ConfigDocument {
	return normalizeConfigDocument(h.state.Config)
}

func (h *Handle) GetConfigValue(key string) (any, error) {
	key = strings.TrimSpace(key)
	doc := h.GetConfig()
	value, ok := doc[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrConfigKeyNotFound, key)
	}
	return cloneConfigValue(value), nil
}

func (h *Handle) SetConfigValue(key string, value any, actors ...string) (ConfigDocument, error) {
	key = strings.TrimSpace(key)
	actor := "user"
	if len(actors) > 0 && strings.TrimSpace(actors[0]) != "" {
		actor = strings.TrimSpace(actors[0])
	}
	spec, ok := configSpecs[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrConfigKeyNotFound, key)
	}
	normalized, err := spec.validate(value)
	if err != nil {
		return nil, err
	}
	unlock := lockVaultStatePath(h.store.paths.StatePath)
	defer unlock()
	envelope, err := h.store.readEnvelopeStrict()
	if err != nil {
		return nil, err
	}
	latest, err := readState(h.vaultKey, envelope.Data)
	if err != nil {
		return nil, err
	}
	h.state = latest
	next := h.GetConfig()
	next[key] = cloneConfigValue(normalized)
	h.state.Config = next
	if err := h.persistUnlocked(); err != nil {
		return nil, err
	}
	h.store.appendAuditBestEffort("config.update", actor, map[string]any{"key": key})
	return h.GetConfig(), nil
}

func normalizeConfigDocument(doc ConfigDocument) ConfigDocument {
	out := make(ConfigDocument, len(configSpecs))
	for key, spec := range configSpecs {
		out[key] = cloneConfigValue(spec.defaultValue)
	}
	for key, value := range doc {
		spec, ok := configSpecs[strings.TrimSpace(key)]
		if !ok {
			continue
		}
		if normalized, err := spec.validate(value); err == nil {
			out[strings.TrimSpace(key)] = cloneConfigValue(normalized)
		}
	}
	return out
}

func validateBool(key string) func(any) (any, error) {
	return func(value any) (any, error) {
		boolValue, ok := value.(bool)
		if !ok {
			return nil, fmt.Errorf("%w: %s must be a boolean", ErrConfigInvalid, key)
		}
		return boolValue, nil
	}
}

func validateIntRange(key string, min int, max int) func(any) (any, error) {
	return func(value any) (any, error) {
		intValue, ok := intFromConfigValue(value)
		if !ok {
			return nil, fmt.Errorf("%w: %s must be an integer", ErrConfigInvalid, key)
		}
		if intValue < min || intValue > max {
			return nil, fmt.Errorf("%w: %s must be between %d and %d", ErrConfigInvalid, key, min, max)
		}
		return intValue, nil
	}
}

func validateString(key string, maxLength int) func(any) (any, error) {
	return func(value any) (any, error) {
		stringValue, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s must be a string", ErrConfigInvalid, key)
		}
		stringValue = strings.TrimSpace(stringValue)
		if len(stringValue) > maxLength {
			return nil, fmt.Errorf("%w: %s is too long", ErrConfigInvalid, key)
		}
		return stringValue, nil
	}
}

func validateEnum(key string, allowed []string) func(any) (any, error) {
	return func(value any) (any, error) {
		stringValue, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%w: %s must be a string", ErrConfigInvalid, key)
		}
		stringValue = strings.TrimSpace(stringValue)
		if !slices.Contains(allowed, stringValue) {
			return nil, fmt.Errorf("%w: %s must be one of %s", ErrConfigInvalid, key, strings.Join(allowed, ", "))
		}
		return stringValue, nil
	}
}

func validateStringSlice(key string, allowed []string) func(any) (any, error) {
	return func(value any) (any, error) {
		values, ok := value.([]string)
		if !ok {
			rawValues, rawOK := value.([]any)
			if !rawOK {
				return nil, fmt.Errorf("%w: %s must be an array of strings", ErrConfigInvalid, key)
			}
			values = make([]string, 0, len(rawValues))
			for _, raw := range rawValues {
				item, itemOK := raw.(string)
				if !itemOK {
					return nil, fmt.Errorf("%w: %s must be an array of strings", ErrConfigInvalid, key)
				}
				values = append(values, item)
			}
		}
		out := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				return nil, fmt.Errorf("%w: %s cannot include empty targets", ErrConfigInvalid, key)
			}
			if !slices.Contains(allowed, value) {
				return nil, fmt.Errorf("%w: %s must include only %s", ErrConfigInvalid, key, strings.Join(allowed, ", "))
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
		slices.Sort(out)
		return out, nil
	}
}

func validateAnyStringSlice(key string) func(any) (any, error) {
	return func(value any) (any, error) {
		values, ok := value.([]string)
		if !ok {
			rawValues, rawOK := value.([]any)
			if !rawOK {
				return nil, fmt.Errorf("%w: %s must be an array of strings", ErrConfigInvalid, key)
			}
			values = make([]string, 0, len(rawValues))
			for _, raw := range rawValues {
				item, itemOK := raw.(string)
				if !itemOK {
					return nil, fmt.Errorf("%w: %s must be an array of strings", ErrConfigInvalid, key)
				}
				values = append(values, item)
			}
		}
		out := make([]string, 0, len(values))
		seen := map[string]struct{}{}
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			if _, ok := seen[value]; ok {
				continue
			}
			seen[value] = struct{}{}
			out = append(out, value)
		}
		slices.Sort(out)
		return out, nil
	}
}

func intFromConfigValue(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		minInt, maxInt := configIntBounds()
		if typed < minInt || typed > maxInt {
			return 0, false
		}
		return int(typed), true
	case float64:
		if typed != float64(int(typed)) {
			return 0, false
		}
		return int(typed), true
	default:
		return 0, false
	}
}

func cloneConfigValue(value any) any {
	switch typed := value.(type) {
	case []string:
		return slices.Clone(typed)
	case []any:
		return slices.Clone(typed)
	default:
		return typed
	}
}
