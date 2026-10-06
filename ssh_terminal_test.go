package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"net"
	"testing"
	"time"
)

func TestSSHProbeObtainsHostIdentityWithoutCredentials(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	authCalled := false
	config := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { authCalled = true; return nil, nil }}
	config.AddHostKey(signer)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, e := listener.Accept()
		if e != nil {
			return
		}
		defer conn.Close()
		_, _, _, _ = ssh.NewServerConn(conn, config)
	}()
	old := sshDial
	defer func() { sshDial = old }()
	sshDial = func(ctx context.Context, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	}
	identity, err := probeSSHIdentity(context.Background(), NetworkEquipment{IP: "192.0.2.20", SSHPort: 22})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not close")
	}
	if authCalled || identity.Fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatal("credential sent before trust or wrong host key")
	}
}
func TestSSHOutputBufferBounded(t *testing.T) {
	terminal := &sshTerminal{}
	data := make([]byte, 2<<20)
	n, err := terminal.Write(data)
	if err != nil || n != len(data) || len(terminal.output) > 1<<20 || terminal.base == 0 {
		t.Fatal("unbounded SSH output")
	}
}
