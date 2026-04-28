package app

// hasp-3wfg: lock the FlagSet vs help-text contract via static analysis.
//
// hasp-4xxh patched the drift for `setup` by editing the help body to
// list every flag manually, and the original test for that fix kept its
// own hand-curated mirror of every FlagSet — which is itself a second
// source of truth that drifts. The real SSOT win is a CI-gated check
// that scrapes every command's *flag.FlagSet definitions out of the
// production package source via go/ast, looks up the matching help
// topic, and asserts every registered flag name appears in the help
// body. New flags can never ship without their help line.
//
// We use AST rather than reflection so we don't have to refactor 20+
// command bodies to expose their FlagSet constructors externally.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// flagRegistrarMethods are the *flag.FlagSet methods whose first
// string-literal argument is the flag name. (We accept VarP/BoolVarP
// spellings so a future swap to spf13/pflag still works with this
// drift test untouched.)
var flagRegistrarMethods = map[string]struct{}{
	"Bool": {}, "BoolVar": {}, "BoolVarP": {},
	"Int": {}, "IntVar": {},
	"Int64": {}, "Int64Var": {},
	"Uint": {}, "UintVar": {},
	"Uint64": {}, "Uint64Var": {},
	"Float64": {}, "Float64Var": {},
	"String": {}, "StringVar": {},
	"Duration": {}, "DurationVar": {},
	"Var": {}, "VarP": {},
	"TextVar": {}, "Func": {},
}

// commandsWithoutHelpTopic lists FlagSet command paths that legitimately
// have no `hasp help <path>` topic (hidden / internal-only commands).
// New entries here are conscious carve-outs — add a one-line rationale.
var commandsWithoutHelpTopic = map[string]string{
	"__complete": "hidden completion entry point (hasp-czal)",
}

// flagsWithoutHelpEntry per command path lists registered flag names
// that are NOT yet documented in the help body. The whole map is
// existing technical debt accumulated before this lint landed
// (hasp-3wfg) — every flag listed here is a real drift that the
// follow-up bead hasp-r40j will drain by adding doc lines. New flags
// MUST NOT be added to this map; the SSOT contract from now on is:
// "register a flag → document it in `hasp help <command>`."
var flagsWithoutHelpEntry = map[string]map[string]string{}

func TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets(t *testing.T) {
	pkgRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkgRoot, func(info os.FileInfo) bool { //nolint:staticcheck // deprecated but adequate for this in-package AST sweep
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.AllErrors)
	if err != nil {
		t.Fatalf("parser.ParseDir: %v", err)
	}
	pkg, ok := pkgs["app"]
	if !ok {
		t.Fatalf("expected package 'app' under %s; got %v", pkgRoot, pkgKeys(pkgs))
	}

	commands := map[string]*flagDriftCmdEntry{}

	for fname, file := range pkg.Files {
		ast.Inspect(file, func(n ast.Node) bool {
			fn, ok := n.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				return true
			}
			currentEntry := (*flagDriftCmdEntry)(nil)
			ast.Inspect(fn.Body, func(inner ast.Node) bool {
				call, ok := inner.(*ast.CallExpr)
				if !ok {
					return true
				}
				if path, ok := newFlagSetPath(call); ok {
					if commands[path] == nil {
						commands[path] = &flagDriftCmdEntry{
							path:  path,
							flags: map[string]struct{}{},
							file:  filepath.Base(fname),
						}
					}
					currentEntry = commands[path]
					return true
				}
				if currentEntry == nil {
					return true
				}
				if name, ok := flagRegistrarName(call); ok {
					currentEntry.flags[name] = struct{}{}
				}
				return true
			})
			return true
		})
	}

	if len(commands) == 0 {
		t.Fatal("ast scan found 0 flag.NewFlagSet sites in the app package — the AST walker is broken")
	}

	// Sanity: setup must be among the scraped commands and must have at
	// least the marquee flags. If this fails, the AST walker missed a site.
	if entry, ok := commands["setup"]; !ok {
		t.Fatalf("ast scan missed flag.NewFlagSet(\"setup\", ...); commands found: %v", cmdPaths(commands))
	} else {
		for _, must := range []string{"non-interactive", "json", "hasp-home", "project-root"} {
			if _, ok := entry.flags[must]; !ok {
				t.Fatalf("ast scan missed --%s for setup; flags found: %v", must, flagKeys(entry.flags))
			}
		}
	}

	for path, entry := range commands {
		if _, skip := commandsWithoutHelpTopic[path]; skip {
			continue
		}
		help, ok := helpBodyForCommand(path)
		if !ok {
			t.Errorf("[%s] flag.NewFlagSet(%q) has no `hasp help %s` topic (and no parent topic); either add help text or list the path in commandsWithoutHelpTopic with rationale (file=%s)",
				path, path, path, entry.file)
			continue
		}
		exempt := flagsWithoutHelpEntry[path]
		for name := range entry.flags {
			if _, ok := exempt[name]; ok {
				continue
			}
			if helpMentionsFlag(help, name) {
				continue
			}
			t.Errorf("[%s] flag --%s is registered in the FlagSet (in %s) but not mentioned in `hasp help %s`; help/FlagSet drift",
				path, name, entry.file, path)
		}
	}
}

// helpBodyForCommand returns the help text for the given command path,
// falling back to the parent topic when a subcommand has no entry of
// its own (e.g. `project bind` defers to `project`).
func helpBodyForCommand(path string) (string, bool) {
	if body, ok := helpTopicByKey[path]; ok {
		return body, true
	}
	if i := strings.LastIndex(path, " "); i > 0 {
		return helpBodyForCommand(path[:i])
	}
	return "", false
}

// newFlagSetPath returns the string-literal command path from a
// flag.NewFlagSet("path", ...) call expression, or false if the call
// doesn't match.
func newFlagSetPath(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok || pkg.Name != "flag" || sel.Sel.Name != "NewFlagSet" {
		return "", false
	}
	if len(call.Args) == 0 {
		return "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	return strings.Trim(lit.Value, `"`), true
}

// flagRegistrarName returns the flag name from any FlagSet method that
// registers a flag, by locating the first string-literal argument.
// fs.Bool("name", false, "usage") -> "name"
// fs.Var(&v, "name", "usage")      -> "name"
func flagRegistrarName(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if _, isFlagMethod := flagRegistrarMethods[sel.Sel.Name]; !isFlagMethod {
		return "", false
	}
	for _, arg := range call.Args {
		lit, ok := arg.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			continue
		}
		return strings.Trim(lit.Value, `"`), true
	}
	return "", false
}

// helpMentionsFlag returns true if the help body documents the given
// flag name. We accept any non-letter follow-on character so renderings
// like "--name <value>", "--name=on", "--name)", "--name," all match.
func helpMentionsFlag(help, name string) bool {
	target := "--" + name
	idx := 0
	for {
		hit := strings.Index(help[idx:], target)
		if hit < 0 {
			return false
		}
		end := idx + hit + len(target)
		if end >= len(help) {
			return true
		}
		next := help[end]
		// Reject "--name…suffix" matches that are actually a different
		// longer flag (e.g. --json should not match --json-output).
		if !isFlagNameChar(next) {
			return true
		}
		idx = end
	}
}

func isFlagNameChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z':
		return true
	case c >= 'A' && c <= 'Z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_':
		return true
	}
	return false
}

func pkgKeys(m map[string]*ast.Package) []string { //nolint:staticcheck // ast.Package is deprecated but parser.ParseDir still returns it
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

type flagDriftCmdEntry struct {
	path  string
	flags map[string]struct{}
	file  string
}

func cmdPaths(m map[string]*flagDriftCmdEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func flagKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
