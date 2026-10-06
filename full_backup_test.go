package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFullRecoveryArchivePreservesConfigurationCredentialsAndLogs(t *testing.T) {
	cert, key, _, err := makeCertificate("siem.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cfg := testApp(t).cfg
	cfg.DataDir = "/var/lib/multipla-siem"
	cfg.TLSCert = "/etc/multipla-siem/tailscale.crt"
	cfg.TLSKey = "/etc/multipla-siem/tailscale.key"
	config, _ := json.Marshal(cfg)
	files := map[string][]byte{
		"multipla-recovery.json":                  []byte(`{"product":"Multipla Siem","schema":1}`),
		"var/lib/multipla-siem/config.json":       config,
		"var/lib/multipla-siem/state.json":        []byte(`{"accounts":{"viewer@example.com":{"role":"viewer"}}}`),
		"var/lib/multipla-siem/logs/events.jsonl": []byte("historical event\n"),
		"etc/multipla-siem/secrets.env":           []byte("GOOGLE_CLIENT_SECRET=private-test-value\n"),
		"etc/multipla-siem/tailscale.crt":         cert,
		"etc/multipla-siem/tailscale.key":         key,
		"var/lib/tailscale/tailscaled.state":      []byte("private-device-identity"),
		"usr/local/bin/multipla-siem":             []byte("binary"),
		"usr/local/lib/multipla-siem/updater":     []byte("updater"),
	}
	var archive bytes.Buffer
	gz := gzip.NewWriter(&archive)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	var encrypted, restored bytes.Buffer
	recovery := bytes.Repeat([]byte{5}, 32)
	if err := encryptFull(&encrypted, &archive, recovery); err != nil {
		t.Fatal(err)
	}
	if err := decryptFull(&restored, &encrypted, recovery); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := extractFull(&restored, stage); err != nil {
		t.Fatal(err)
	}
	for name, expected := range files {
		actual, err := os.ReadFile(filepath.Join(stage, filepath.FromSlash(name)))
		if err != nil || !bytes.Equal(actual, expected) {
			t.Fatalf("lost recovery file %s: %v", name, err)
		}
	}
}

func TestFullEncryptionAuthenticatedChunks(t *testing.T) {
	key := bytes.Repeat([]byte{9}, 32)
	plain := bytes.Repeat([]byte("credential-and-log\n"), 100000)
	var encrypted, restored bytes.Buffer
	if err := encryptFull(&encrypted, bytes.NewReader(plain), key); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encrypted.Bytes(), []byte("credential-and-log")) {
		t.Fatal("plaintext leak")
	}
	if err := decryptFull(&restored, bytes.NewReader(encrypted.Bytes()), key); err != nil || !bytes.Equal(restored.Bytes(), plain) {
		t.Fatal("roundtrip", err)
	}
	for _, variant := range []string{"wrong-key", "tamper", "truncate", "append", "sequence"} {
		data := append([]byte{}, encrypted.Bytes()...)
		testKey := key
		switch variant {
		case "wrong-key":
			testKey = bytes.Repeat([]byte{8}, 32)
		case "tamper":
			data[30] ^= 1
		case "truncate":
			data = data[:len(data)-1]
		case "append":
			data = append(data, 0)
		case "sequence":
			data[19] = 8
		}
		if decryptFull(&bytes.Buffer{}, bytes.NewReader(data), testKey) == nil {
			t.Fatal("accepted", variant)
		}
	}
}

func TestFullArchiveRejectsPathsLinksAndBombs(t *testing.T) {
	for _, h := range []*tar.Header{
		{Name: "../../etc/passwd", Typeflag: tar.TypeReg, Mode: 0600},
		{Name: "/etc/multipla-siem/secrets.env", Typeflag: tar.TypeReg, Mode: 0600},
		{Name: "etc/multipla-siem/key", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "var/lib/multipla-siem/logs/bomb", Typeflag: tar.TypeReg, Size: fullBackupLimit + 1},
	} {
		var data bytes.Buffer
		gz := gzip.NewWriter(&data)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Close()
		gz.Close()
		if extractFull(bytes.NewReader(data.Bytes()), t.TempDir()) == nil {
			t.Fatal("accepted", h.Name)
		}
	}
}

func TestFullRecoveryKeyNotOverwritten(t *testing.T) {
	file := filepath.Join(t.TempDir(), "recovery.key")
	first, err := recoveryKey(file, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := recoveryKey(file, true)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("key changed", err)
	}
	if err = os.WriteFile(file, []byte("invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = recoveryKey(file, false); err == nil {
		t.Fatal("accepted invalid key")
	}
}

func TestFullDriveUploadHostCannotLeakCredentials(t *testing.T) {
	for _, url := range []string{"http://www.googleapis.com/upload/drive/v3/files?upload_id=a", "https://evil.example/upload/drive/v3/files?upload_id=a", "https://www.googleapis.com.evil.example/upload/drive/v3/files?upload_id=a", "https://user@www.googleapis.com/upload/drive/v3/files?upload_id=a", "https://www.googleapis.com:443/upload/drive/v3/files?upload_id=a", "https://www.googleapis.com/other?upload_id=a"} {
		if validFullUploadURL(url) {
			t.Fatal("accepted unauthorized upload destination", url)
		}
	}
	if !validFullUploadURL("https://www.googleapis.com/upload/drive/v3/files?upload_id=valid") {
		t.Fatal("rejected Google upload session")
	}
}
