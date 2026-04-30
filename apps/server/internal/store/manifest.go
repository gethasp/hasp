package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
)

const (
	ManifestClassificationSecret       = "secret"
	ManifestClassificationPublicConfig = "public_config"
	ManifestDeliveryEnv                = "env"
	ManifestDeliveryFile               = "file"
	ManifestDeliveryXCConfig           = "xcconfig"
	ManifestExampleEnv                 = "env"
	ManifestExampleXCConfig            = "xcconfig"
)

var (
	manifestTargetNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	manifestDestinationPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

type ManifestTargetExpansion struct {
	TargetName   string            `json:"target"`
	TargetRoot   string            `json:"target_root"`
	ManifestHash string            `json:"manifest_hash"`
	Command      []string          `json:"command,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	Files        map[string]string `json:"files,omitempty"`
	XCConfig     map[string]string `json:"xcconfig,omitempty"`
	Outputs      map[string]string `json:"outputs,omitempty"`
	Refs         []string          `json:"refs"`
	Destinations []string          `json:"destinations"`
}

type ManifestReview struct {
	ProjectRoot  string            `json:"project_root"`
	TargetName   string            `json:"target"`
	ManifestHash string            `json:"manifest_hash"`
	Signature    ManifestSignature `json:"signature"`
	ReviewedAt   time.Time         `json:"reviewed_at"`
}

type ManifestSignature struct {
	Command  string `json:"command"`
	Refs     string `json:"refs"`
	Delivery string `json:"delivery"`
	Outputs  string `json:"outputs"`
}

type ManifestDrift struct {
	Known           bool   `json:"known"`
	Changed         bool   `json:"changed"`
	CommandChanged  bool   `json:"command_changed"`
	RefsChanged     bool   `json:"refs_changed"`
	DeliveryChanged bool   `json:"delivery_changed"`
	OutputsChanged  bool   `json:"outputs_changed"`
	PreviousHash    string `json:"previous_manifest_hash,omitempty"`
	CurrentHash     string `json:"current_manifest_hash,omitempty"`
}

func (e ManifestTargetExpansion) ExecutionRoot(projectRoot string) string {
	targetRoot := strings.TrimSpace(e.TargetRoot)
	if targetRoot == "" || targetRoot == "." {
		return projectRoot
	}
	return filepath.Join(projectRoot, filepath.Clean(targetRoot))
}

func (e ManifestTargetExpansion) Signature() ManifestSignature {
	return ManifestSignature{
		Command:  hashManifestValue(e.Command),
		Refs:     hashManifestValue(e.Refs),
		Delivery: hashManifestValue(manifestDeliverySignature(e)),
		Outputs:  hashManifestValue(manifestStringMapSignature(e.Outputs)),
	}
}

func (h *Handle) ManifestTargetDrift(projectRoot string, expansion ManifestTargetExpansion) (ManifestDrift, error) {
	if strings.TrimSpace(expansion.TargetName) == "" {
		return ManifestDrift{}, nil
	}
	key, root, err := manifestReviewKey(projectRoot, expansion.TargetName)
	if err != nil {
		return ManifestDrift{}, err
	}
	review, ok := h.state.ManifestReviews[key]
	if !ok {
		return ManifestDrift{Known: false, CurrentHash: expansion.ManifestHash}, nil
	}
	current := expansion.Signature()
	drift := ManifestDrift{
		Known:          true,
		PreviousHash:   review.ManifestHash,
		CurrentHash:    expansion.ManifestHash,
		CommandChanged: review.Signature.Command != current.Command,
		RefsChanged:    review.Signature.Refs != current.Refs,
		OutputsChanged: review.Signature.Outputs != current.Outputs,
	}
	drift.DeliveryChanged = review.Signature.Delivery != current.Delivery
	drift.Changed = drift.CommandChanged || drift.RefsChanged || drift.OutputsChanged || drift.DeliveryChanged || review.ProjectRoot != root
	return drift, nil
}

func (h *Handle) RecordManifestTargetReview(projectRoot string, expansion ManifestTargetExpansion) error {
	if strings.TrimSpace(expansion.TargetName) == "" {
		return nil
	}
	key, root, err := manifestReviewKey(projectRoot, expansion.TargetName)
	if err != nil {
		return err
	}
	if h.state.ManifestReviews == nil {
		h.state.ManifestReviews = map[string]ManifestReview{}
	}
	h.state.ManifestReviews[key] = ManifestReview{
		ProjectRoot:  root,
		TargetName:   expansion.TargetName,
		ManifestHash: expansion.ManifestHash,
		Signature:    expansion.Signature(),
		ReviewedAt:   h.store.now(),
	}
	return h.persist()
}

func manifestReviewKey(projectRoot string, targetName string) (string, string, error) {
	root, err := CanonicalProjectPath(projectRoot)
	if err != nil {
		return "", "", err
	}
	targetName = strings.TrimSpace(targetName)
	return root + "\x00" + targetName, root, nil
}

func hashManifestValue(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func manifestDeliverySignature(expansion ManifestTargetExpansion) []string {
	values := make([]string, 0, len(expansion.Env)+len(expansion.Files)+len(expansion.XCConfig))
	values = append(values, manifestMapEntries(ManifestDeliveryEnv, expansion.Env)...)
	values = append(values, manifestMapEntries(ManifestDeliveryFile, expansion.Files)...)
	values = append(values, manifestMapEntries(ManifestDeliveryXCConfig, expansion.XCConfig)...)
	slices.Sort(values)
	return values
}

func manifestMapEntries(prefix string, values map[string]string) []string {
	entries := make([]string, 0, len(values))
	for key, value := range values {
		entries = append(entries, prefix+":"+strings.TrimSpace(key)+"="+strings.TrimSpace(value))
	}
	return entries
}

func manifestStringMapSignature(values map[string]string) []string {
	entries := make([]string, 0, len(values))
	for key, value := range values {
		entries = append(entries, strings.TrimSpace(key)+"="+strings.TrimSpace(value))
	}
	slices.Sort(entries)
	return entries
}

func LoadRepoManifestWithIdentity(root string) (RepoManifest, string, error) {
	path := filepath.Join(root, manifestFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		return RepoManifest{}, "", err
	}
	manifest, err := DecodeRepoManifest(root, data)
	if err != nil {
		return RepoManifest{}, "", err
	}
	sum := sha256.Sum256(data)
	return manifest, hex.EncodeToString(sum[:]), nil
}

func DecodeRepoManifest(root string, data []byte) (RepoManifest, error) {
	if err := rejectManifestLocalAuthorityFields(data); err != nil {
		return RepoManifest{}, err
	}
	var manifest RepoManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return RepoManifest{}, fmt.Errorf("decode repo manifest: %w", err)
	}
	if err := manifest.Validate(root); err != nil {
		return RepoManifest{}, err
	}
	return manifest, nil
}

func (m RepoManifest) Validate(root string) error {
	if strings.TrimSpace(m.Version) == "" {
		if manifestHasExtendedFields(m) {
			return errors.New("repo manifest version is required when requirements or targets are declared")
		}
	} else if strings.TrimSpace(m.Version) != "v1" {
		return fmt.Errorf("unsupported repo manifest version %q", m.Version)
	}

	requirements := map[string]ManifestRequirement{}
	for _, req := range m.Requirements {
		ref := strings.TrimSpace(req.Ref)
		if ref == "" {
			return errors.New("manifest requirement ref is required")
		}
		if _, exists := requirements[ref]; exists {
			return fmt.Errorf("duplicate manifest requirement ref %q", ref)
		}
		switch req.Kind {
		case ItemKindKV, ItemKindFile:
		default:
			return fmt.Errorf("unknown manifest requirement kind %q for %s", req.Kind, ref)
		}
		switch strings.TrimSpace(req.Classification) {
		case ManifestClassificationSecret, ManifestClassificationPublicConfig:
		default:
			return fmt.Errorf("unknown manifest requirement classification %q for %s", req.Classification, ref)
		}
		if !m.manifestReferenceDeclared(ref) {
			return fmt.Errorf("manifest requirement %q is not declared in references", ref)
		}
		requirements[ref] = req
	}

	targetNames := map[string]string{}
	for _, target := range m.Targets {
		name := strings.TrimSpace(target.Name)
		if !manifestTargetNamePattern.MatchString(name) || strings.ContainsAny(name, `/\`) || containsControl(name) {
			return fmt.Errorf("unsafe manifest target name %q", target.Name)
		}
		lower := strings.ToLower(name)
		if existing, ok := targetNames[lower]; ok {
			return fmt.Errorf("duplicate manifest target name %q conflicts with %q", name, existing)
		}
		targetNames[lower] = name
		if err := validateManifestRelativePath(root, target.Root, "target root", false); err != nil {
			return err
		}
		for _, arg := range target.Command {
			if strings.TrimSpace(arg) == "" || containsControl(arg) {
				return fmt.Errorf("manifest target %q contains an empty or unsafe command argument", name)
			}
		}
		deliveryNames := map[string]struct{}{}
		for _, delivery := range target.Delivery {
			if err := validateManifestDelivery(name, delivery, requirements); err != nil {
				return err
			}
			key := strings.ToLower(strings.TrimSpace(delivery.Name))
			if _, exists := deliveryNames[key]; exists {
				return fmt.Errorf("duplicate delivery name %q in target %q", delivery.Name, name)
			}
			deliveryNames[key] = struct{}{}
			if strings.TrimSpace(delivery.Output) != "" {
				if delivery.As != ManifestDeliveryXCConfig {
					return fmt.Errorf("output is not allowed for %s delivery %q in target %q", delivery.As, delivery.Name, name)
				}
				if err := validateManifestRelativePath(root, delivery.Output, "delivery output", true); err != nil {
					return err
				}
			}
		}
		for _, example := range target.Examples {
			switch strings.TrimSpace(example.Format) {
			case ManifestExampleEnv, ManifestExampleXCConfig:
			default:
				return fmt.Errorf("unknown manifest example format %q in target %q", example.Format, name)
			}
			if err := validateManifestRelativePath(root, example.Path, "example path", true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m RepoManifest) manifestReferenceDeclared(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if itemName, ok := parseNamedReference(ref); ok {
		for _, candidate := range m.References {
			if strings.TrimSpace(candidate.Item) == itemName {
				return true
			}
		}
		return false
	}
	for _, candidate := range m.References {
		if strings.TrimSpace(candidate.Alias) == ref {
			return true
		}
	}
	return false
}

func manifestHasExtendedFields(m RepoManifest) bool {
	return len(m.Requirements) > 0 || len(m.Targets) > 0 ||
		strings.TrimSpace(m.Project.Name) != "" || strings.TrimSpace(m.Project.Description) != ""
}

func validateManifestDelivery(targetName string, delivery ManifestDelivery, requirements map[string]ManifestRequirement) error {
	as := strings.TrimSpace(delivery.As)
	switch as {
	case ManifestDeliveryEnv, ManifestDeliveryFile, ManifestDeliveryXCConfig:
	default:
		return fmt.Errorf("unknown delivery format %q in target %q", delivery.As, targetName)
	}
	name := strings.TrimSpace(delivery.Name)
	if !manifestDestinationPattern.MatchString(name) || manifestDangerousDestination(name) {
		return fmt.Errorf("unsafe delivery destination %q in target %q", delivery.Name, targetName)
	}
	ref := strings.TrimSpace(delivery.Ref)
	req, ok := requirements[ref]
	if !ok {
		return fmt.Errorf("delivery %q in target %q references unknown requirement %q", name, targetName, delivery.Ref)
	}
	if req.Kind == ItemKindFile && as != ManifestDeliveryFile {
		return fmt.Errorf("file requirement %q cannot be delivered as %s in target %q", ref, as, targetName)
	}
	return nil
}

func validateManifestRelativePath(root string, value string, label string, required bool) error {
	value = strings.TrimSpace(value)
	if value == "" {
		if required {
			return fmt.Errorf("%s is required", label)
		}
		return nil
	}
	if filepath.IsAbs(value) {
		return fmt.Errorf("%s %q must be relative to the project root", label, value)
	}
	clean := filepath.Clean(value)
	if clean == "." && required {
		return fmt.Errorf("%s %q must name a file below the project root", label, value)
	}
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s %q escapes the project root", label, value)
	}
	if root == "" {
		return nil
	}
	projectRoot, err := filepathAbsFn(root)
	if err != nil {
		return err
	}
	if resolvedRoot, err := filepath.EvalSymlinks(projectRoot); err == nil {
		projectRoot = resolvedRoot
	}
	candidate := filepath.Join(projectRoot, clean)
	resolvedCandidate, err := resolveManifestPathSymlinks(candidate)
	if err != nil {
		return err
	}
	candidate = resolvedCandidate
	if candidate != projectRoot && !strings.HasPrefix(candidate, projectRoot+string(filepath.Separator)) {
		return fmt.Errorf("%s %q escapes the project root", label, value)
	}
	return nil
}

func resolveManifestPathSymlinks(candidate string) (string, error) {
	candidate, err := filepathAbsFn(candidate)
	if err != nil {
		return "", err
	}
	probe := candidate
	for {
		resolved, err := filepath.EvalSymlinks(probe)
		if err == nil {
			if probe == candidate {
				return resolved, nil
			}
			rel, _ := filepath.Rel(probe, candidate)
			return filepath.Join(resolved, rel), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(probe)
		probe = parent
	}
}

func manifestDangerousDestination(name string) bool {
	upper := strings.ToUpper(strings.TrimSpace(name))
	switch upper {
	case "PATH", "LD_PRELOAD", "NODE_OPTIONS", "PYTHONPATH", "RUBYOPT", "SSH_AUTH_SOCK", "HOME", "SHELL":
		return true
	}
	for _, prefix := range []string{"DYLD_", "GIT_", "HASP_"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func containsControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func rejectManifestLocalAuthorityFields(data []byte) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil
	}
	var walk func(any) error
	walk = func(value any) error {
		switch v := value.(type) {
		case map[string]any:
			for key, child := range v {
				switch strings.ToLower(strings.TrimSpace(key)) {
				case "value", "values", "grant", "grants", "convenience_grants", "tokens", "session_token", "workspace_trust":
					return fmt.Errorf("repo manifest must not contain local authority or secret value field %q", key)
				}
				if err := walk(child); err != nil {
					return err
				}
			}
		case []any:
			for _, child := range v {
				if err := walk(child); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(raw)
}

func (m RepoManifest) Target(name string) (ManifestTarget, bool) {
	name = strings.TrimSpace(name)
	for _, target := range m.Targets {
		if target.Name == name {
			return target, true
		}
	}
	return ManifestTarget{}, false
}

func (m RepoManifest) Requirement(ref string) (ManifestRequirement, bool) {
	ref = strings.TrimSpace(ref)
	for _, req := range m.Requirements {
		if req.Ref == ref {
			return req, true
		}
	}
	return ManifestRequirement{}, false
}

func (m RepoManifest) ItemNameForRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if itemName, ok := parseNamedReference(ref); ok && itemName != "" {
		return itemName, true
	}
	for _, manifestRef := range m.References {
		if strings.TrimSpace(manifestRef.Alias) == ref {
			return strings.TrimSpace(manifestRef.Item), true
		}
	}
	return "", false
}

func ExpandManifestTarget(root string, targetName string) (ManifestTargetExpansion, error) {
	manifest, identity, err := LoadRepoManifestWithIdentity(root)
	if err != nil {
		return ManifestTargetExpansion{}, err
	}
	target, ok := manifest.Target(targetName)
	if !ok {
		return ManifestTargetExpansion{}, fmt.Errorf("unknown manifest target %q", targetName)
	}
	expansion := ManifestTargetExpansion{
		TargetName:   target.Name,
		TargetRoot:   target.Root,
		ManifestHash: identity,
		Command:      slices.Clone(target.Command),
		Env:          map[string]string{},
		Files:        map[string]string{},
		XCConfig:     map[string]string{},
		Outputs:      map[string]string{},
	}
	for _, delivery := range target.Delivery {
		name := strings.TrimSpace(delivery.Name)
		ref := strings.TrimSpace(delivery.Ref)
		switch delivery.As {
		case ManifestDeliveryEnv:
			expansion.Env[name] = ref
		case ManifestDeliveryFile:
			expansion.Files[name] = ref
		case ManifestDeliveryXCConfig:
			expansion.XCConfig[name] = ref
			if strings.TrimSpace(delivery.Output) != "" {
				expansion.Outputs[name] = strings.TrimSpace(delivery.Output)
			}
		}
		expansion.Refs = append(expansion.Refs, ref)
		expansion.Destinations = append(expansion.Destinations, name)
	}
	slices.Sort(expansion.Refs)
	expansion.Refs = slices.Compact(expansion.Refs)
	slices.Sort(expansion.Destinations)
	expansion.Destinations = slices.Compact(expansion.Destinations)
	return expansion, nil
}
