package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"net"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func syntheticDHCPCapture(server [4]byte, relay bool, kind byte) []byte {
	boot := make([]byte, 240)
	boot[0] = 2
	copy(boot[16:20], []byte{192, 168, 10, 42})
	if relay {
		copy(boot[24:28], []byte{192, 168, 10, 1})
	}
	copy(boot[236:], []byte{99, 130, 83, 99})
	boot = append(boot, 53, 1, kind, 54, 4)
	boot = append(boot, server[:]...)
	boot = append(boot, 1, 4, 255, 255, 255, 0, 255)
	frame := make([]byte, 14+20+8)
	copy(frame[6:12], []byte{0, 17, 34, 51, 68, 85})
	binary.BigEndian.PutUint16(frame[12:14], 0x800)
	ip := frame[14:]
	ip[0] = 0x45
	ip[9] = 17
	copy(ip[12:16], server[:])
	if relay {
		copy(ip[12:16], []byte{192, 168, 10, 1})
	}
	binary.BigEndian.PutUint16(ip[2:4], uint16(28+len(boot)))
	binary.BigEndian.PutUint16(ip[20:22], 67)
	binary.BigEndian.PutUint16(ip[22:24], 68)
	binary.BigEndian.PutUint16(ip[24:26], uint16(8+len(boot)))
	frame = append(frame, boot...)
	out := make([]byte, 40)
	copy(out, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(out[4:6], 2)
	binary.LittleEndian.PutUint16(out[6:8], 4)
	binary.LittleEndian.PutUint32(out[16:20], 1500)
	binary.LittleEndian.PutUint32(out[20:24], 1)
	binary.LittleEndian.PutUint32(out[32:36], uint32(len(frame)))
	binary.LittleEndian.PutUint32(out[36:40], uint32(len(frame)))
	return append(out, frame...)
}

func TestDHCPSSHExecReturnsStructuredEvidenceWithoutCredential(t *testing.T) {
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
	config := &ssh.ServerConfig{PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) { return nil, nil }}
	config.AddHostKey(signer)
	commands := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		server, channels, requests, err := ssh.NewServerConn(conn, config)
		if err != nil {
			return
		}
		defer server.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			channel, reqs, err := incoming.Accept()
			if err != nil {
				return
			}
			for request := range reqs {
				if request.Type == "exec" {
					var payload struct{ Command string }
					ssh.Unmarshal(request.Payload, &payload)
					commands <- payload.Command
					request.Reply(true, nil)
					channel.Write(syntheticDHCPCapture([4]byte{192, 168, 10, 1}, false, 2))
					channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
					channel.Close()
					break
				} else {
					request.Reply(false, nil)
				}
			}
		}
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	c, ch, req, err := ssh.NewClientConn(conn, listener.Addr().String(), &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{ssh.Password("SYNTHETIC_ONLY_SECRET")}, HostKeyCallback: ssh.FixedHostKey(signer.PublicKey())})
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(c, ch, req)
	defer client.Close()
	a := testApp(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	job := &dhcpJob{id: "synthetic", owner: "admin@gmail.com", status: "capturing", cancel: cancel}
	terminal := &sshTerminal{client: client, status: "connected"}
	command, err := dhcpCaptureCommand("igb1", 15)
	if err != nil {
		t.Fatal(err)
	}
	dhcpSlots <- struct{}{}
	a.runDHCP(ctx, job, terminal, command)
	if job.status != "completed" || len(job.servers) != 1 || job.servers[0].IP != "192.168.10.1" {
		t.Fatal(job.status, job.message, job.servers)
	}
	sent := <-commands
	if sent != command || strings.Contains(sent, "SYNTHETIC_ONLY_SECRET") {
		t.Fatal("unexpected command or credential exposure")
	}
}
func TestDHCPRepliesExtractEvidenceAndKeepRelayDistinct(t *testing.T) {
	data := syntheticDHCPCapture([4]byte{192, 168, 10, 2}, false, 2)
	data = append(data, syntheticDHCPCapture([4]byte{192, 168, 10, 2}, false, 2)[24:]...)
	data = append(data, syntheticDHCPCapture([4]byte{192, 168, 20, 1}, true, 5)[24:]...)
	found, err := parseDHCPCapture(data)
	if err != nil || len(found) != 2 {
		t.Fatalf("%+v %v", found, err)
	}
	if found[0].IP != "192.168.10.2" || found[0].MAC != "00:11:22:33:44:55" || found[0].Responses != 2 || found[0].Network != "192.168.10.0/24" || found[0].Relay {
		t.Fatalf("bad evidence %+v", found[0])
	}
	if !found[1].Relay || found[1].Source != "192.168.10.1" {
		t.Fatalf("relay lost %+v", found[1])
	}
}
func TestDHCPMalformedAndRequestsNeverBecomeServers(t *testing.T) {
	data := syntheticDHCPCapture([4]byte{192, 168, 10, 1}, false, 1)
	found, err := parseDHCPCapture(data)
	if err != nil || len(found) != 0 {
		t.Fatal(found, err)
	}
	for _, n := range []int{0, 10, 25, len(data) - 1} {
		if _, err := parseDHCPCapture(data[:n]); err == nil {
			t.Fatalf("truncation accepted %d", n)
		}
	}
	data[40+14+6] = 0x20
	found, err = parseDHCPCapture(data)
	if err != nil || len(found) != 0 {
		t.Fatal("fragment accepted")
	}
}
func TestDHCPCommandRejectsInjectionAndEnforcesBounds(t *testing.T) {
	for _, iface := range []string{"igb1;id", "-i", "igb1\nwhoami", "$(id)", "igb1'", ""} {
		if _, err := dhcpCaptureCommand(iface, 30); err == nil {
			t.Fatal(iface)
		}
	}
	for _, n := range []int{0, 9, 121, 10000} {
		if _, err := dhcpCaptureCommand("igb1", n); err == nil {
			t.Fatal(n)
		}
	}
	c, err := dhcpCaptureCommand("igb1.10", 30)
	if err != nil || !strings.Contains(c, "sleep 30") || !strings.Contains(c, "-c 1000") || !strings.Contains(c, "trap cleanup") {
		t.Fatal(c, err)
	}
}
func TestDHCPLimitsOutputAndDoesNotExposeViewerRoutes(t *testing.T) {
	cancelled := false
	b := &limitedCapture{limit: 4, cancel: func() { cancelled = true }}
	b.Write([]byte("abcd"))
	if _, err := b.Write([]byte("secret")); err == nil || !cancelled || !bytes.Equal(b.copy(), []byte("abcd")) {
		t.Fatal("capture limit")
	}
	a := testApp(t)
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Role: "viewer"}}
	for _, path := range []string{"/api/ssh/sessions/t/dhcp/interfaces", "/api/ssh/sessions/t/dhcp/j"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", path, nil))
		if w.Code != 403 {
			t.Fatalf("viewer %s %d", path, w.Code)
		}
	}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, testRequest("POST", "/api/ssh/sessions/t/dhcp", strings.NewReader(`{}`)))
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func FuzzDHCPCapture(f *testing.F) {
	f.Add(syntheticDHCPCapture([4]byte{192, 168, 10, 1}, false, 2))
	f.Add([]byte("bad"))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 2<<20 {
			return
		}
		_, _ = parseDHCPCapture(data)
	})
}
