package app

// hasp-zm7q (GREEN Stage 3): extend the flag-drift scanner to cover
// internal/app/agentops/ so that TestAgentopsFlagDriftCoverage passes.
//
// TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets only scans the
// package app directory; agentops/ is a sibling package with its own
// flag.NewFlagSet calls. This file re-runs the same AST scan over
// agentops/ and asserts every registered flag is mentioned in the
// corresponding `hasp agent <subcommand>` help topic.

import (
	"go/ast"
	"go/token"
	"os"
	"path/filepath"
	"testing"
)

func TestAgentopsFlagDriftCoverage(t *testing.T) {
	pkgRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	agentopsDir := filepath.Join(pkgRoot, "agentops")
	if _, err := os.Stat(agentopsDir); err != nil {
		t.Skipf("agentops/ directory not found at %s: %v", agentopsDir, err)
	}

	fset := token.NewFileSet()
	pkgs, err := parseNonTestPackageFiles(fset, agentopsDir)
	if err != nil {
		t.Fatalf("parse package files %s: %v", agentopsDir, err)
	}
	files, ok := pkgs["agentops"]
	if !ok {
		t.Fatalf("expected package 'agentops' under %s; got %v", agentopsDir, pkgKeys(pkgs))
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

	// agentops commands map to "agent <subcommand>" help topics in package app.
	// e.g. flag.NewFlagSet("agent connect", ...) → helpBodyForCommand("agent connect")
	for path, entry := range commands {
		if _, skip := commandsWithoutHelpTopic[path]; skip {
			continue
		}
		help, ok := helpBodyForCommand(path)
		if !ok {
			t.Errorf("[agentops][%s] flag.NewFlagSet(%q) has no `hasp help %s` topic; add help text or exempt the path (file=%s)",
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
			t.Errorf("[agentops][%s] flag --%s is in the FlagSet (in %s) but not in `hasp help %s`",
				path, name, entry.file, path)
		}
	}
}
