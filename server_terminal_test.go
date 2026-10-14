package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServerTerminalFixedTargetAndExplicitLinuxUser(t *testing.T) {
	a := testApp(t)
	d, err := a.sshEquipment(localServerSSHID)
	if err != nil || d.IP != "127.0.0.1" || d.SSHPort != 22 || d.Kind != "server" || d.SSHUser != "" {
		t.Fatal("local SSH target must be fixed and require an explicit user", d, err)
	}
	if _, err = a.sshEquipment("127.0.0.1:2222"); err == nil {
		t.Fatal("arbitrary target accepted")
	}
	a.demo = false
	a.nativeTLS = true
	for _, body := range []string{
		`{"id":"__multipla_local_server__","password":"temporary"}`,
		`{"id":"__multipla_local_server__","user":"   ","password":"temporary"}`,
		`{"id":"__multipla_local_server__","user":"bad;user","password":"temporary"}`,
		`{"id":"__multipla_local_server__","user":"siemadmin","password":"temporary","ip":"192.0.2.1"}`,
	} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/ssh/sessions", []byte(body)))
		if w.Code != 400 {
			t.Fatalf("invalid local request accepted: %d %s", w.Code, w.Body.String())
		}
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/ssh/sessions", []byte(`{"id":"__multipla_local_server__","user":"siemadmin","password":"temporary"}`)))
	if w.Code != 400 {
		t.Fatal("local terminal must require confirmed host identity", w.Code, w.Body.String())
	}
	if len(a.sshTerminals) != 0 {
		t.Fatal("session created before trust")
	}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	for _, path := range []string{"/api/ssh/identity", "/api/ssh/trust", "/api/ssh/sessions"} {
		w = httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", path, []byte(`{"id":"__multipla_local_server__"}`)))
		if w.Code != 403 {
			t.Fatal("viewer local SSH access", path, w.Code)
		}
	}
}

func TestServerTerminalUsesSSHKeyAndInteractiveChannel(t *testing.T) {
	_, hostPrivate, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPrivate)
	_, clientPrivate, _ := ed25519.GenerateKey(rand.Reader)
	clientSigner, _ := ssh.NewSignerFromKey(clientPrivate)
	oldDelegated := delegatedSSHAuth
	defer func() { delegatedSSHAuth = oldDelegated }()
	delegatedSSHAuth = func(ctx context.Context, d NetworkEquipment, owner string) (ssh.AuthMethod, error) {
		if d.SSHUser != "multipla-ops" || owner != "admin@gmail.com" {
			return nil, io.EOF
		}
		return ssh.PublicKeys(clientSigner), nil
	}
	block, err := ssh.MarshalPrivateKey(clientPrivate, "test-only")
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan string, 1)
	config := &ssh.ServerConfig{PublicKeyCallback: func(info ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if info.User() != "multipla-ops" || !bytes.Equal(key.Marshal(), clientSigner.PublicKey().Marshal()) {
			return nil, io.EOF
		}
		return &ssh.Permissions{}, nil
	}}
	config.AddHostKey(hostSigner)
	go func() {
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		server, channels, requests, e := ssh.NewServerConn(conn, config)
		if e != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for next := range channels {
			if next.ChannelType() != "session" {
				next.Reject(ssh.UnknownChannelType, "session only")
				continue
			}
			channel, requests, e := next.Accept()
			if e != nil {
				return
			}
			defer channel.Close()
			for request := range requests {
				switch request.Type {
				case "pty-req":
					request.Reply(true, nil)
				case "shell":
					request.Reply(true, nil)
					channel.Write([]byte("READY\r\n"))
					buffer := make([]byte, 64)
					n, e := channel.Read(buffer)
					if e != nil {
						return
					}
					channel.Write(buffer[:n])
					received <- string(buffer[:n])
					return
				default:
					request.Reply(false, nil)
				}
			}
		}
	}()
	oldDial := sshDial
	defer func() { sshDial = oldDial }()
	sshDial = func(ctx context.Context, address string) (net.Conn, error) {
		if address != "127.0.0.1:22" {
			t.Errorf("unexpected target: %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	a := testApp(t)
	a.demo = false
	a.nativeTLS = true
	a.state.SSHHostKeys = map[string]SSHHostIdentity{localServerSSHID: {IP: "127.0.0.1", Port: 22, Key: base64.StdEncoding.EncodeToString(hostSigner.PublicKey().Marshal()), Fingerprint: ssh.FingerprintSHA256(hostSigner.PublicKey())}}
	_ = pem.EncodeToMemory(block) // test key never enters an HTTP body
	body, _ := json.Marshal(map[string]string{"id": localServerSSHID, "user": "multipla-ops"})
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/ssh/sessions", body))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		ID string `json:"id"`
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	terminal := a.sshTerminals[result.ID]
	defer terminal.close("test complete")
	deadline := time.Now().Add(5 * time.Second)
	for {
		terminal.mu.Lock()
		status := terminal.status
		terminal.mu.Unlock()
		if status == "connected" {
			break
		}
		if status == "closed" || time.Now().After(deadline) {
			t.Fatal("SSH did not connect", status)
		}
		time.Sleep(10 * time.Millisecond)
	}
	input, _ := json.Marshal(map[string]string{"data": base64.StdEncoding.EncodeToString([]byte("echo-check\r"))})
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/ssh/sessions/"+result.ID+"/input", input))
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	select {
	case data := <-received:
		if data != "echo-check\r" {
			t.Fatal(data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interactive input not delivered")
	}
	state, _ := json.Marshal(a.state)
	if strings.Contains(string(state), "OPENSSH PRIVATE KEY") {
		t.Fatal("private key persisted")
	}
}
