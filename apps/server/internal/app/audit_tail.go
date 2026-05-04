package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/gethasp/hasp/apps/server/internal/audit"
)

// auditTailOpts captures the runtime knobs the audit tail loop needs.
// Construction is explicit at dispatch time so tests can pass a tighter
// PollInterval without sharing a package-level mutable seam.
type auditTailOpts struct {
	PollInterval time.Duration
}

// defaultAuditTailOpts returns the production defaults. A 500ms poll keeps
// live tailing snappy without thrashing the disk.
func defaultAuditTailOpts() auditTailOpts {
	return auditTailOpts{PollInterval: 500 * time.Millisecond}
}

// auditTailNowFn is a seam tests substitute to make --since deterministic
// against fixed event timestamps (hasp-eddo).
var auditTailNowFn = time.Now

func auditTailCommand(ctx context.Context, args []string, stdout io.Writer, opts auditTailOpts) error {
	if opts.PollInterval <= 0 {
		opts.PollInterval = 500 * time.Millisecond
	}
	fs := flag.NewFlagSet("audit tail", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var lines int
	fs.IntVar(&lines, "n", 50, "")
	var follow bool
	fs.BoolVar(&follow, "follow", false, "")
	fs.BoolVar(&follow, "f", false, "")
	var jsonOutput bool
	fs.BoolVar(&jsonOutput, "json", false, "")
	var allFlag bool
	fs.BoolVar(&allFlag, "all", false, "")
	var sinceFlag time.Duration
	fs.DurationVar(&sinceFlag, "since", 0, "")
	filterSecret := fs.String("secret", "", "")
	filterProjectRoot := fs.String("project-root", "", "")
	filterAgent := fs.String("agent", "", "")
	filterAction := fs.String("action", "", "")
	filterBlocked := fs.Bool("blocked", false, "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: hasp audit tail [-n N | --all] [--since DUR] [-f] [--json] [filters]")
	}
	nExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "n" {
			nExplicit = true
		}
	})
	if allFlag && nExplicit {
		return errors.New("--all and -n are mutually exclusive")
	}
	if !allFlag && lines <= 0 {
		return errors.New("--n: must be a positive integer")
	}
	if sinceFlag < 0 {
		return errors.New("--since: must be a positive duration")
	}
	sinceExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "since" {
			sinceExplicit = true
		}
	})
	if sinceExplicit && sinceFlag == 0 {
		return errors.New("--since: must be a positive duration")
	}
	if expandedRoot, expandErr := expandUserPath(strings.TrimSpace(*filterProjectRoot)); expandErr != nil {
		return fmt.Errorf("--project-root: %w", expandErr)
	} else {
		*filterProjectRoot = expandedRoot
	}

	var blockedPtr *bool
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "blocked" {
			v := *filterBlocked
			blockedPtr = &v
		}
	})
	filterOpts := auditFilterOptions{
		Secret:      *filterSecret,
		ProjectRoot: *filterProjectRoot,
		Agent:       *filterAgent,
		Action:      *filterAction,
		Blocked:     blockedPtr,
	}
	hasFilters := filterOpts.Secret != "" || filterOpts.ProjectRoot != "" ||
		filterOpts.Agent != "" || filterOpts.Action != "" || filterOpts.Blocked != nil

	log, err := newAuditLogFn()
	if err != nil {
		return err
	}
	if log != nil {
		if key := getAuditHMACKey(); len(key) > 0 {
			log = log.WithKey(key)
		} else if handle, oerr := openVaultHandleFn(ctx); oerr == nil && handle != nil {
			log = log.WithKey(handle.AuditHMACKey())
		}
	}

	all, err := auditEventsFn(log)
	if err != nil {
		return err
	}
	// Track the last sequence we have seen — even if filters drop the slice to
	// zero, the follow loop must not re-emit historical events on the next
	// tick. We compute this from the unfiltered slice before pruning.
	var lastSeq int64
	for _, e := range all {
		if e.Sequence > lastSeq {
			lastSeq = e.Sequence
		}
	}

	initial := all
	if hasFilters {
		initial = auditFilterEvents(initial, filterOpts)
	}
	if sinceFlag > 0 {
		cutoff := auditTailNowFn().Add(-sinceFlag)
		filtered := make([]audit.Event, 0, len(initial))
		for _, e := range initial {
			if !e.Timestamp.Before(cutoff) {
				filtered = append(filtered, e)
			}
		}
		initial = filtered
	}
	if !allFlag && len(initial) > lines {
		initial = initial[len(initial)-lines:]
	}
	if err := renderAuditTail(initial, jsonOutput, stdout); err != nil {
		return err
	}
	if !follow {
		return nil
	}

	ticker := time.NewTicker(opts.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			fresh, err := auditEventsFn(log)
			if err != nil {
				return err
			}
			deltas := make([]audit.Event, 0)
			for _, e := range fresh {
				if e.Sequence > lastSeq {
					deltas = append(deltas, e)
					lastSeq = e.Sequence
				}
			}
			if len(deltas) == 0 {
				continue
			}
			if hasFilters {
				deltas = auditFilterEvents(deltas, filterOpts)
			}
			if len(deltas) == 0 {
				continue
			}
			if err := renderAuditTail(deltas, jsonOutput, stdout); err != nil {
				return err
			}
		}
	}
}

func renderAuditTail(events []audit.Event, jsonOutput bool, w io.Writer) error {
	if jsonOutput {
		for _, e := range events {
			payload := redactAuditEvent(e)
			line, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintln(w, string(line)); err != nil {
				return err
			}
		}
		return nil
	}
	return auditRenderTimeline(events, w)
}
