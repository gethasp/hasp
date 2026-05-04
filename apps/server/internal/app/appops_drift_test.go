package app

// hasp-1v77 (GREEN Stage 4): extend the flag-drift scanner to cover
// internal/app/appops/ so that TestAppopsFlagDriftCoverage passes.
//
// TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets only scans the
// package app directory; appops/ is a sibling package with its own
// flag.NewFlagSet calls (routed through deps.NewFlagSet which the
// defaultNewFlagSet variable delegates to). This file re-runs the same
// AST scan over appops/ and asserts every registered flag is mentioned in
// the corresponding `hasp app <subcommand>` help topic.

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestAppopsFlagDriftCoverage(t *testing.T) {
	pkgRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	appopsDir := filepath.Join(pkgRoot, "appops")
	if _, err := os.Stat(appopsDir); err != nil {
		t.Skipf("appops/ directory not found at %s: %v", appopsDir, err)
	}

	fset := token.NewFileSet()
	pkgs, err := parseNonTestPackageFiles(fset, appopsDir)
	if err != nil {
		t.Fatalf("parse package files %s: %v", appopsDir, err)
	}
	files, ok := pkgs["appops"]
	if !ok {
		t.Fatalf("expected package 'appops' under %s; got %v", appopsDir, pkgKeys(pkgs))
	}

	commands := map[string]*flagDriftCmdEntry{}

	for fname, file := range files {
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

	// appops commands map to "app <subcommand>" help topics in package app.
	// e.g. flag.NewFlagSet("app connect", ...) → helpBodyForCommand("app connect")
	for path, entry := range commands {
		if _, skip := commandsWithoutHelpTopic[path]; skip {
			continue
		}
		help, ok := helpBodyForCommand(path)
		if !ok {
			t.Errorf("[appops][%s] flag.NewFlagSet(%q) has no `hasp help %s` topic; add help text or exempt the path (file=%s)",
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
			t.Errorf("[appops][%s] flag --%s is in the FlagSet (in %s) but not in `hasp help %s`",
				path, name, entry.file, path)
		}
	}
}
