package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestSSHSessionRequiresDurableStartAudit(t *testing.T) {
	a := testApp(t)
	a.demo = false
	a.nativeTLS = true
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	a.state.SSHHostKeys = map[string]SSHHostIdentity{localServerSSHID: {IP: "127.0.0.1", Port: 22, Key: base64.StdEncoding.EncodeToString(key.Marshal())}}
	a.cfg.DataDir = filepath.Join(t.TempDir(), "missing", "directory")
	body := fmt.Sprintf(`{"id":%q,"user":"audituser","password":"audit-secret-never-log"}`, localServerSSHID)
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/ssh/sessions", []byte(body)))
	if w.Code != 503 || len(a.sshTerminals) != 0 {
		t.Fatal("SSH started without durable audit", w.Code)
	}
	for _, entry := range a.state.Audit {
		if strings.Contains(entry.Action, "audit-secret") {
			t.Fatal("credential in audit")
		}
	}
}
func TestSSHSessionCloseAudit(t *testing.T) {
	a := testApp(t)
	_, cancel := context.WithCancel(context.Background())
	a.sshTerminals = map[string]*sshTerminal{"audit": {owner: "admin@gmail.com", status: "connected", cancel: cancel, equipment: NetworkEquipment{Name: "audit-target"}}}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/ssh/sessions/audit/close", []byte(`{}`)))
	if w.Code != 200 || len(a.state.Audit) == 0 || !strings.Contains(a.state.Audit[len(a.state.Audit)-1].Action, "encerrado") {
		t.Fatal("close audit missing", w.Code)
	}
}
