package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestSignedManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	raw := []byte(`{"version":"1.2.1","arch":"amd64","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":100,"updater_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","updater_size":100}`)
	sig := ed25519.Sign(priv, raw)
	if _, e := verify(raw, sig, pub, "amd64"); e != nil {
		t.Fatal(e)
	}
	if _, e := verify(raw, sig, pub, "arm64"); e == nil {
		t.Fatal("accepted foreign architecture")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, e := verify(raw, sig, other, "amd64"); e == nil {
		t.Fatal("accepted untrusted key")
	}
	raw[12] = '9'
	if _, e := verify(raw, sig, pub, "amd64"); e == nil {
		t.Fatal("accepted tamper")
	}
	if _, e := verify(raw, sig, pub, "arm64"); e == nil {
		t.Fatal("accepted foreign architecture")
	}
}
func TestDownloadDomains(t *testing.T) {
	for _, h := range []string{"github.com.evil.example", "127.0.0.1", "169.254.169.254", "evil.example"} {
		if permitted(h) {
			t.Fatal(h)
		}
	}
	for _, h := range []string{"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"} {
		if !permitted(h) {
			t.Fatal(h)
		}
	}
}
