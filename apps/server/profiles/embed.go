package profilesdata

import "embed"

// FS carries the shipped first-class support profile manifests.
//
//go:embed *.json
var FS embed.FS
