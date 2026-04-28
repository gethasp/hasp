package app

// hasp-wvse Stage 2 RED: boundary tests for the package-app wrapper.
//
// These tests verify two things:
//  1. The existing secretCommand(ctx, args, ...) entrypoint in package app
//     still behaves correctly after migration (wrapper-to-secretops delegation).
//  2. The AST-based FlagSet drift lint (TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets)
//     will cover the secretops package once the GREEN team lands it. Because that
//     test scans only package "app" source via go/ast on pkgRoot (os.Getwd),
//     the flag drift lint won't automatically reach internal/app/secretops/.
//     This test documents the gap and provides a hook for GREEN to extend it.

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"strings"
	"testing"
)

// TestSecretBoundaryHelpStillWorks asserts that the package-app secretCommand
// entrypoint (which will become a thin wrapper around secretops.SecretCommand
// after Stage 2d) still returns nil and writes help text for the "help" arg.
//
// On main this test PASSES (secretCommand is the real implementation).
// After GREEN's migration it will continue to PASS via the wrapper.
// If GREEN removes secretCommand from package app without wiring a wrapper,
// this test will fail to compile — RED signal.
func TestSecretBoundaryHelpStillWorks(t *testing.T) {
	lockAppSeams(t)
	var out bytes.Buffer
	err := secretCommand(context.Background(), []string{"help"}, strings.NewReader(""), &out, io.Discard)
	if err != nil {
		t.Fatalf("secretCommand(help) returned %v; want nil", err)
	}
	if out.Len() == 0 {
		t.Fatal("secretCommand(help) produced no output; expected help text")
	}
}

// TestSecretBoundaryUnknownSubcommand asserts that the package-app wrapper
// surfaces the unknown-subcommand error after migration.
func TestSecretBoundaryUnknownSubcommand(t *testing.T) {
	lockAppSeams(t)
	err := secretCommand(context.Background(), []string{"no-such-subcommand-xyzzy"}, strings.NewReader(""), io.Discard, io.Discard)
	if err == nil {
		t.Fatal("secretCommand(no-such-subcommand-xyzzy) returned nil; want an error")
	}
}

// TestSecretopsFlagDriftCoverageGap documents that the existing
// TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets scanner operates only
// on package "app" source (it calls os.Getwd() = internal/app/) and will NOT
// automatically scan internal/app/secretops/ after migration.
//
// This test:
//   - confirms the scanner parses only package "app" (not sub-packages), and
//   - FAILS if internal/app/secretops/ already contains non-test .go files
//     that define flag.NewFlagSet calls that the parent scanner won't see.
//
// When the GREEN team lands secretops production code they must either:
//   a) extend the drift scanner to also walk internal/app/secretops/, or
//   b) make the secretops FlagSet registrations visible inside package app
//      (e.g. by calling them from app-level command bodies that the scanner
//      already walks), and delete/modify this test accordingly.
func TestSecretopsFlagDriftCoverageGap(t *testing.T) {
	pkgRoot, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}

	// Confirm the existing scanner only covers "app", not sub-packages.
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, pkgRoot, func(info os.FileInfo) bool { //nolint:staticcheck
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.AllErrors)
	if err != nil {
		t.Fatalf("parser.ParseDir: %v", err)
	}
	if _, ok := pkgs["app"]; !ok {
		t.Fatalf("expected package 'app' at %s; got %v", pkgRoot, pkgKeys(pkgs))
	}

	// Now scan internal/app/secretops/ for production files with flag.NewFlagSet.
	secretopsDir := pkgRoot + "/secretops"
	info, err := os.Stat(secretopsDir)
	if err != nil || !info.IsDir() {
		// Directory doesn't exist yet — GREEN hasn't landed; nothing to check.
		t.Skip("internal/app/secretops/ does not exist yet; skipping gap check")
	}

	secretopsFset := token.NewFileSet()
	secretopsPkgs, err := parser.ParseDir(secretopsFset, secretopsDir, func(info os.FileInfo) bool { //nolint:staticcheck
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, parser.AllErrors)
	if err != nil {
		t.Fatalf("parser.ParseDir secretops: %v", err)
	}

	for _, pkg := range secretopsPkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if _, ok := newFlagSetPath(call); ok {
					// Found a FlagSet in secretops that the parent scanner won't see.
					t.Errorf(
						"internal/app/secretops/ contains flag.NewFlagSet call(s) that are "+
							"invisible to TestHelpTextMentionsEveryFlagDefinedInPackageFlagSets. "+
							"GREEN team must extend the drift scanner to cover secretops/ or "+
							"route FlagSet registrations through package app. "+
							"See TestSecretopsFlagDriftCoverageGap in secretops_boundary_test.go.",
					)
					return false
				}
				return true
			})
		}
	}
}
