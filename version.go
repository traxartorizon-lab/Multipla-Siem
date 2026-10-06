package main

import (
	_ "embed"
	"strings"
	"time"
)

//go:embed VERSION
var productVersionFile string

func productVersion() string { return strings.TrimSpace(productVersionFile) }
func driveBackupFilename(full bool, now time.Time) string {
	kind, extension := "config", ".json"
	if full {
		kind, extension = "full", ".msbk"
	}
	return "Multipla-Siem-v" + productVersion() + "-" + kind + "-" + now.UTC().Format("20060102-150405") + extension
}
