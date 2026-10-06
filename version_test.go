package main

import (
	"strings"
	"testing"
	"time"
)

func TestBackupNamesIncludeProductVersionKindAndUTC(t *testing.T) {
	now := time.Date(2026, 10, 6, 14, 0, 0, 0, time.FixedZone("test", -3*3600))
	config := driveBackupFilename(false, now)
	full := driveBackupFilename(true, now)
	if !strings.HasPrefix(config, "Multipla-Siem-v"+productVersion()+"-config-") || !strings.HasSuffix(config, "20261006-170000.json") {
		t.Fatal(config)
	}
	if !strings.HasPrefix(full, "Multipla-Siem-v"+productVersion()+"-full-") || !strings.HasSuffix(full, "20261006-170000.msbk") {
		t.Fatal(full)
	}
	if productVersion() == "" || strings.ContainsAny(productVersion(), "\r\n /") {
		t.Fatal("invalid version")
	}
}
