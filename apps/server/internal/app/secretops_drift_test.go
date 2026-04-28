package app

// hasp-sgdq (GREEN Stage 2): extend the flag-drift scanner to cover
// internal/app/secretops/ so that TestSecretopsFlagDriftCoverageGap passes.
//
// TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets only scans the
// package app directory; secretops/ is a sibling package with its own
// flag.NewFlagSet calls. This file re-runs the same AST scan over
// secretops/ and asserts every registered flag is mentioned in the
// corresponding `hasp secret <subcommand>` help topic.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretopsFlagDriftCoverage(t *testing.T) {
	pkgRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	secretopsDir := filepath.Join(pkgRoot, "secretops")
	if _, err := os.Stat(secretopsDir); err != nil {
		t.Skipf("secretops/ directory not found at %s: %v", secretopsDir, err)
	}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, secretopsDir, func(info os.FileInfo) bool { //nolint:staticcheck // ast.Package deprecated but parser.ParseDir returns it
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.AllErrors)
	if err != nil {
		t.Fatalf("parser.ParseDir(%s): %v", secretopsDir, err)
	}
	pkg, ok := pkgs["secretops"]
	if !ok {
		t.Fatalf("expected package 'secretops' under %s; got %v", secretopsDir, pkgKeys(pkgs))
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

	// secretops commands map to "secret <subcommand>" help topics in package app.
	// e.g. flag.NewFlagSet("secret add", ...) → helpBodyForCommand("secret add")
	for path, entry := range commands {
		if _, skip := commandsWithoutHelpTopic[path]; skip {
			continue
		}
		help, ok := helpBodyForCommand(path)
		if !ok {
			t.Errorf("[secretops][%s] flag.NewFlagSet(%q) has no `hasp help %s` topic; add help text or exempt the path (file=%s)",
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
			t.Errorf("[secretops][%s] flag --%s is in the FlagSet (in %s) but not in `hasp help %s`",
				path, name, entry.file, path)
		}
	}
}
