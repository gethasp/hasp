package app

// hasp-nwym (GREEN Stage 5b): extend the flag-drift scanner to cover
// internal/app/sessionops/ so that TestSessionopsFlagDriftCoverage passes.
//
// TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets only scans the
// package app directory; sessionops/ is a sibling package with its own
// flag.NewFlagSet calls. This file re-runs the same AST scan over
// sessionops/ and asserts every registered flag is mentioned in the
// corresponding `hasp session <subcommand>` help topic.

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionopsFlagDriftCoverage(t *testing.T) {
	pkgRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	sessionopsDir := filepath.Join(pkgRoot, "sessionops")
	if _, err := os.Stat(sessionopsDir); err != nil {
		t.Skipf("sessionops/ directory not found at %s: %v", sessionopsDir, err)
	}

	fset := token.NewFileSet()
	pkgs, err := parseNonTestPackageFiles(fset, sessionopsDir)
	if err != nil {
		t.Fatalf("parse package files %s: %v", sessionopsDir, err)
	}
	files, ok := pkgs["sessionops"]
	if !ok {
		t.Fatalf("expected package 'sessionops' under %s; got %v", sessionopsDir, pkgKeys(pkgs))
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

	// sessionops commands map to "session <subcommand>" help topics in package app.
	// e.g. flag.NewFlagSet("session open", ...) → helpBodyForCommand("session open")
	for path, entry := range commands {
		if _, skip := commandsWithoutHelpTopic[path]; skip {
			continue
		}
		help, ok := helpBodyForCommand(path)
		if !ok {
			t.Errorf("[sessionops][%s] flag.NewFlagSet(%q) has no `hasp help %s` topic; add help text or exempt the path (file=%s)",
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
			t.Errorf("[sessionops][%s] flag --%s is in the FlagSet (in %s) but not in `hasp help %s`",
				path, name, entry.file, path)
		}
	}
}
