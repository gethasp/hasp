package app

import (
	"flag"
	"sort"
	"strings"
)

// buildUsageLine renders a `usage: hasp <command> [--flag ...]` string
// directly from a FlagSet so usage messages stay in sync with the
// actual flag surface (hasp-28um). Each flag is rendered as
// `[--name]` for booleans and `[--name <value>]` for value flags;
// flag names are sorted for stable output.
func buildUsageLine(commandPath string, fs *flag.FlagSet) string {
	if fs == nil {
		return "usage: hasp " + commandPath
	}
	type flagSpec struct {
		name     string
		argLabel string
	}
	specs := make([]flagSpec, 0)
	fs.VisitAll(func(f *flag.Flag) {
		specs = append(specs, flagSpec{name: f.Name, argLabel: usageArgLabel(f)})
	})
	if len(specs) == 0 {
		return "usage: hasp " + commandPath
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].name < specs[j].name })

	var b strings.Builder
	b.WriteString("usage: hasp ")
	b.WriteString(commandPath)
	for _, s := range specs {
		b.WriteByte(' ')
		b.WriteByte('[')
		b.WriteString("--")
		b.WriteString(s.name)
		if s.argLabel != "" {
			b.WriteByte(' ')
			b.WriteString(s.argLabel)
		}
		b.WriteByte(']')
	}
	return b.String()
}

// usageArgLabel returns the `<value>` placeholder for non-boolean flags. We
// rely on the flag's Value type rather than parsing the usage string so the
// label stays stable when handlers don't bother setting a usage string
// (most don't, since hasp keeps human-facing help text in help.go).
func usageArgLabel(f *flag.Flag) string {
	if f == nil {
		return ""
	}
	type boolFlag interface {
		IsBoolFlag() bool
	}
	if b, ok := f.Value.(boolFlag); ok && b.IsBoolFlag() {
		return ""
	}
	return "<value>"
}
