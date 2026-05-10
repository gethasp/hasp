package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
)

// CompletionOptions controls optional behaviour of the shell completion engine.
type CompletionOptions struct {
	// IncludeSecretNames controls whether secret names are surfaced as
	// completions. This is an opt-in privacy tradeoff.
	IncludeSecretNames bool
}

// secretSubcommands is the canonical list of subcommands under `hasp secret`.
// Mirrors the switch in secretCommand so completions never lag the dispatcher.
var secretSubcommands = []string{
	"add", "copy", "delete", "diff", "expose", "get",
	"hide", "list", "reveal", "rotate", "search", "show", "update",
}

var projectSubcommands = []string{
	"adopt", "bind", "doctor", "examples", "requirements", "status", "targets", "unbind",
}

var policySubcommands = []string{
	"set", "show", "validate",
}

var configSubcommands = []string{
	"get", "set", "show",
}

// subcommandMap maps a root command name to its known subcommands.
// Only entries that have meaningful sub-dispatch are listed; unlisted
// commands will return an empty slice.
func subcommandMap() map[string][]string {
	return map[string][]string{
		"config":  configSubcommands,
		"policy":  policySubcommands,
		"project": projectSubcommands,
		"secret":  secretSubcommands,
	}
}

// runFlagNames returns the flag names (without leading --) defined for
// `hasp run` / `hasp inject` by constructing the same flag.FlagSet that
// executeCommandWithDeps uses and collecting them.
func runFlagNames() []string {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.String("project-root", ".", "")
	fs.String("session-token", "", "")
	fs.String("grant-project", "", "")
	fs.String("grant-secret", "", "")
	fs.Duration("grant-window", 0, "")
	fs.Bool("explain", false, "")
	fs.Bool("dry-run", false, "")
	fs.String("explain-format", "text", "")
	var envRefs mappingFlag
	var fileRefs mappingFlag
	fs.Var(&envRefs, "env", "")
	fs.Var(&fileRefs, "file", "")

	var names []string
	fs.VisitAll(func(f *flag.Flag) {
		names = append(names, "--"+f.Name)
	})
	sort.Strings(names)
	return names
}

// Complete returns shell-completion candidates for the given partial argument
// list.
//
//   - Complete(nil or []) returns visible root-level command names.
//   - Complete(["secret"]) returns subcommands of `hasp secret`.
//   - Complete(["run", "--"]) returns flag names for `hasp run`.
//   - All other patterns return nil (no completions).
func Complete(args []string, _ CompletionOptions) []string {
	// Root-level completion.
	if len(args) == 0 {
		specs := rootCommandInventory()
		names := make([]string, 0, len(specs))
		for _, spec := range specs {
			if !spec.hidden {
				names = append(names, spec.name)
			}
		}
		sort.Strings(names)
		return names
	}

	cmd := args[0]

	// Flag completion: hasp <cmd> --...
	if len(args) >= 2 && strings.HasPrefix(args[len(args)-1], "--") {
		switch cmd {
		case "run", "inject":
			return runFlagNames()
		}
		return nil
	}

	// Subcommand completion: hasp <cmd> <partial or empty>
	if subs, ok := subcommandMap()[cmd]; ok {
		return subs
	}

	return nil
}

// RenderBashCompletionScript returns a bash completion script that descends
// into subcommands so `hasp secret <TAB>` produces subcommand names.
func RenderBashCompletionScript() (string, error) {
	rootNames := completionCommandNames()

	var b strings.Builder
	writeBashCompletion(&b, rootNames) //nolint:errcheck // strings.Builder never errors
	return b.String(), nil
}

// RenderZshCompletionScript returns a zsh completion script that dispatches
// per-subcommand so `hasp secret <TAB>` produces subcommand names.
func RenderZshCompletionScript() (string, error) {
	rootNames := completionCommandNames()

	var b strings.Builder
	writeZshCompletion(&b, rootNames) //nolint:errcheck // strings.Builder never errors
	return b.String(), nil
}

// completionCommand emits a shell-completion script for the requested
// shell. The list of completable commands is derived from the live
// rootCommandInventory so a shell completion never lags the dispatcher.
func completionCommand(_ context.Context, args []string, stdout io.Writer, _ io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: hasp completion <bash|zsh|fish|powershell>")
	}
	shell := strings.ToLower(strings.TrimSpace(args[0]))
	commands := completionCommandNames()
	switch shell {
	case "bash":
		return writeBashCompletion(stdout, commands)
	case "zsh":
		return writeZshCompletion(stdout, commands)
	case "fish":
		return writeFishCompletion(stdout, commands)
	case "powershell", "pwsh":
		return writePowershellCompletion(stdout, commands)
	default:
		return fmt.Errorf("unsupported shell %q (want bash, zsh, fish, or powershell)", shell)
	}
}

func completionCommandNames() []string {
	specs := rootCommandInventory()
	names := make([]string, 0, len(specs)+2)
	for _, spec := range specs {
		names = append(names, spec.name)
	}
	// Top-level dispatch also accepts these forms even though they are not
	// in rootCommandInventory; surface them so users can tab-complete to
	// the help and bootstrap entry points.
	names = append(names, "help", "bootstrap")
	sort.Strings(names)
	return uniqueSorted(names)
}

func uniqueSorted(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, value := range in[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}

func writeBashCompletion(w io.Writer, _ []string) error {
	// hasp-czal: delegate every completion request to `hasp __complete` so the
	// shell script never re-encodes the dispatcher tree. COMP_CWORD>=1 hands
	// the words after the program name (including the partial current word) to
	// the binary, which knows the live root inventory, secret subcommands, and
	// run/inject flags.
	body := `# bash completion for hasp
_hasp_complete() {
    local cur="${COMP_WORDS[COMP_CWORD]}"
    local words=("${COMP_WORDS[@]:1:COMP_CWORD}")
    local out
    out="$(hasp __complete "${words[@]}" 2>/dev/null)"
    COMPREPLY=( $(compgen -W "${out}" -- "$cur") )
    return 0
}
complete -F _hasp_complete hasp
`
	_, err := io.WriteString(w, body)
	return err
}

func writeZshCompletion(w io.Writer, _ []string) error {
	// hasp-czal: delegate to `hasp __complete` so subcommand-, flag-, and
	// future deeper completions all flow through one entry point.
	body := `#compdef hasp
# zsh completion for hasp
_hasp_complete() {
    local -a candidates
    local -a words_tail
    words_tail=("${words[@]:1}")
    candidates=("${(@f)$(hasp __complete "${words_tail[@]}" 2>/dev/null)}")
    compadd -- "${candidates[@]}"
}
compdef _hasp_complete hasp
`
	_, err := io.WriteString(w, body)
	return err
}

func writeFishCompletion(w io.Writer, _ []string) error {
	// hasp-czal: pull every completion from `hasp __complete` (which already
	// strips hidden commands and dispatches secret/run subargs) instead of
	// hard-coding a single shallow `__fish_use_subcommand` rule per name.
	body := `# fish completion for hasp
function __hasp_complete
    set -l tokens (commandline -opc)
    set -l current (commandline -ct)
    set -l args $tokens[2..]
    if test -n "$current"
        set args $args $current
    end
    hasp __complete $args 2>/dev/null
end
complete -c hasp -f -a '(__hasp_complete)'
`
	_, err := io.WriteString(w, body)
	return err
}

func writePowershellCompletion(w io.Writer, _ []string) error {
	// hasp-czal: shell out to `hasp __complete` so PowerShell completion
	// follows the live dispatcher (subcommands, flags) instead of a static
	// root-only list.
	body := `# powershell completion for hasp
Register-ArgumentCompleter -Native -CommandName hasp -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $tokens = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
    if ($tokens.Count -ge 1) { $tokens = $tokens[1..($tokens.Count - 1)] } else { $tokens = @() }
    & hasp __complete @tokens 2>$null |
        Where-Object { $_ -like "$wordToComplete*" } |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
}
`
	_, err := io.WriteString(w, body)
	return err
}
