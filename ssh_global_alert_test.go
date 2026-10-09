package main

import (
	"testing"
	"time"
)

func TestGlobalSSHThresholdAcrossDevicesAndIPs(t *testing.T) {
	a := testApp(t)
	base := time.Now().UTC()
	emit := func(i int, ip string, when time.Time) {
		a.evaluateGlobalSSH(Event{ID: token(), Time: when, Device: []string{"Firewall", "Linux"}[i%2], Kind: "generic", Protocol: "syslog"}, `sshd: Failed password for invalid user test from `+ip+` port 47046 ssh2`)
	}
	for i := 0; i < 9; i++ {
		emit(i, "203.0.113.42", base.Add(time.Duration(i)*time.Second))
	}
	if len(a.events) != 0 {
		t.Fatal("early alert")
	}
	emit(9, "203.0.113.43", base.Add(9*time.Second))
	if len(a.events) != 0 {
		t.Fatal("mixed IPs counted")
	}
	emit(9, "203.0.113.42", base.Add(10*time.Second))
	if len(a.events) != 1 || a.events[0].Rule != sshInvasionTitle || a.events[0].Detector != "ssh-login-burst" || len(a.state.Blocks) != 0 {
		t.Fatal("missing global alert or unexpected block")
	}
	for i := 10; i < 20; i++ {
		emit(i, "203.0.113.42", base.Add(time.Duration(i)*time.Second))
	}
	if len(a.events) != 1 {
		t.Fatal("cooldown missing")
	}
}
func TestGlobalSSHRejectsExpiredWindowAndDuplicateInvalidUser(t *testing.T) {
	a := testApp(t)
	base := time.Now().UTC()
	for i := 0; i < 10; i++ {
		a.evaluateGlobalSSH(Event{ID: token(), Time: base.Add(time.Duration(i) * 10 * time.Second), Protocol: "syslog", Kind: "generic"}, `sshd: Failed password for invalid user test from 203.0.113.42 port 22 ssh2`)
	}
	for i := 0; i < 10; i++ {
		a.evaluateGlobalSSH(Event{ID: token(), Time: base, Protocol: "syslog"}, `sshd: Invalid user test from 203.0.113.42 port 22`)
	}
	if len(a.events) != 0 {
		t.Fatal("expired or duplicate record counted")
	}
}
