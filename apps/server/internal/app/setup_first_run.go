package app

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/gethasp/hasp/apps/server/internal/audit"
	"github.com/gethasp/hasp/apps/server/internal/store"
)

func setupOptionalFirstRunActions(ctx context.Context, prompt *setupPrompter, handle *store.Handle, projectRoot string) ([]secretMutationView, []setupAppOutcome, error) {
	if prompt == nil {
		return nil, nil, nil
	}
	addedSecrets, err := setupMaybeAddSecretsNow(ctx, prompt, handle, projectRoot)
	if err != nil {
		return nil, nil, err
	}
	apps, err := setupMaybeConnectAppNow(ctx, prompt, handle, projectRoot)
	if err != nil {
		return nil, nil, err
	}
	return addedSecrets, apps, nil
}

func setupMaybeAddSecretsNow(ctx context.Context, prompt *setupPrompter, handle *store.Handle, projectRoot string) ([]secretMutationView, error) {
	addNow, err := promptBool(prompt, "Add a secret to your vault now", false)
	if err != nil || !addNow {
		return nil, err
	}
	secretPrompt := &secretPrompt{
		reader: prompt.reader,
		stdin:  setupPromptReader(prompt),
		stdout: prompt.out,
		stderr: prompt.out,
	}
	inputs, err := secretAddInputs(nil, secretPrompt)
	if err != nil {
		return nil, err
	}
	exposeNow := false
	if strings.TrimSpace(projectRoot) != "" {
		exposeNow, err = promptBool(prompt, "Expose added secrets to the protected repo now", false)
		if err != nil {
			return nil, err
		}
	}
	added := make([]secretMutationView, 0, len(inputs))
	for _, input := range inputs {
		name, value, outcome, err := resolveSecretAddCollision(handle, input.name, input.value, "", secretPrompt)
		if err != nil {
			return nil, err
		}
		if outcome == "skipped" {
			added = append(added, secretMutationView{Name: input.name, Outcome: outcome})
			continue
		}
		item, err := secretUpsertItemFn(handle, name, store.ItemKindKV, value, store.ItemMetadata{})
		if err != nil {
			return nil, err
		}
		view := secretMutationView{Name: item.Name, Kind: item.Kind, Outcome: outcome}
		if exposeNow {
			reference, err := secretBindItemAliasFn(handle, ctx, projectRoot, item.Name)
			if err != nil {
				return nil, err
			}
			view.ProjectRoot = projectRoot
			view.Reference = reference
		}
		added = append(added, view)
		appendSecretAuditCLI(audit.EventCapture, map[string]any{
			"action":       "secret.add",
			"surface":      "cli",
			"actor_label":  secretActorLabel(),
			"item_name":    item.Name,
			"item_kind":    item.Kind,
			"project_root": view.ProjectRoot,
			"reference":    view.Reference,
			"outcome":      outcome,
		})
	}
	return added, nil
}

func setupMaybeConnectAppNow(ctx context.Context, prompt *setupPrompter, handle *store.Handle, projectRoot string) ([]setupAppOutcome, error) {
	connectNow, err := promptBool(prompt, "Connect an app now", false)
	if err != nil || !connectNow {
		return nil, err
	}
	cfg := appConnectConfig{}
	if strings.TrimSpace(projectRoot) != "" {
		useRepo, err := promptBool(prompt, "Tie this app to the protected repo now", false)
		if err != nil {
			return nil, err
		}
		if useRepo {
			cfg.ProjectRoot = projectRoot
		}
	}
	if err := appConnectPromptMissing(prompt, &cfg); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, fmt.Errorf("app name is required")
	}
	if strings.TrimSpace(cfg.Command) == "" {
		return nil, fmt.Errorf("app command is required")
	}
	if err := validateAppConsumerName(cfg.Name); err != nil {
		return nil, err
	}
	installLauncher, err := promptBool(prompt, fmt.Sprintf("Install launcher command %q", cfg.Name), false)
	if err != nil {
		return nil, err
	}
	cfg.InstallLauncher = setupOptionalBool{set: true, value: installLauncher}
	if installLauncher {
		resolved, err := appResolvePathsFn()
		if err != nil {
			return nil, err
		}
		launcherDir := filepath.Join(resolved.HomeDir, "bin")
		if !pathContainsDir(pathEnvValue(), launcherDir) {
			addToPath, err := promptBool(prompt, fmt.Sprintf("Add %s to your shell PATH", launcherDir), false)
			if err != nil {
				return nil, err
			}
			cfg.AddToPath = setupOptionalBool{set: true, value: addToPath}
		}
	}
	consumer, pathUpdate, err := connectAppConsumerWithHandle(ctx, handle, cfg, nil, prompt.out, prompt.out)
	if err != nil {
		return nil, err
	}
	return []setupAppOutcome{{
		Name:         consumer.Name,
		ProjectRoot:  consumer.ProjectRoot,
		LauncherPath: consumer.LauncherPath,
		PathUpdate:   pathUpdate,
	}}, nil
}

func setupPromptReader(prompt *setupPrompter) io.Reader {
	if prompt.file != nil {
		return prompt.file
	}
	return prompt.reader
}

func pathEnvValue() string {
	return strings.TrimSpace(os.Getenv("PATH"))
}
