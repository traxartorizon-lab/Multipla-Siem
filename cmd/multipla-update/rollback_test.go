package main

import (
	"os"
	"path/filepath"
	"testing"
)

func makeTestSnapshot(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "snapshot")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range snapshotNames {
		data := []byte("test-binary")
		if filepath.Ext(name) == ".json" {
			data = []byte(`{"valid":true}`)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestRollbackSnapshotIntegrityAndLegacy(t *testing.T) {
	dir := makeTestSnapshot(t)
	if err := validateSnapshot(dir); err != nil {
		t.Fatal("legacy snapshot:", err)
	}
	if err := writeSnapshotManifest(dir); err != nil {
		t.Fatal(err)
	}
	if err := validateSnapshot(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "binary"), []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if validateSnapshot(dir) == nil {
		t.Fatal("accepted changed binary")
	}
}

func TestRollbackRejectsIncompleteAndInvalidJSON(t *testing.T) {
	dir := makeTestSnapshot(t)
	if err := os.Remove(filepath.Join(dir, "updater")); err != nil {
		t.Fatal(err)
	}
	if validateSnapshot(dir) == nil {
		t.Fatal("accepted partial snapshot")
	}
	dir = makeTestSnapshot(t)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if validateSnapshot(dir) == nil {
		t.Fatal("accepted invalid state")
	}
}

func TestRollbackBackupIDsPreventTraversal(t *testing.T) {
	for _, id := range []string{"../config", "/tmp/update-20261005T100000.000000000Z", "update-20261005T100000.000000000Z/../x", "before-rollback-20261005T100000.000000000Z"} {
		if backupIDPattern.MatchString(id) {
			t.Fatal("accepted unsafe ID:", id)
		}
	}
	if !backupIDPattern.MatchString("update-20261005T100000.000000000Z") {
		t.Fatal("rejected legitimate snapshot")
	}
}
