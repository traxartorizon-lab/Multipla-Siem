package main

import (
	"fmt"
	"testing"
	"time"
)

func TestPFSenseSSHSourceFormats(t *testing.T) {
	cases := map[string]string{
		`sshd[79944]: Timeout before authentication for connection from 147.90.234.22 to 179.60.129.193, pid = 42680`: "147.90.234.22",
		`sshd-session[42680]: Failed password for invalid user bonus from 147.90.234.22 port 36936 ssh2`:              "147.90.234.22",
		`sshguard[13689]: Blocking "147.90.234.22/32" for 86400 secs (1 attacks in 0 secs)`:                           "147.90.234.22",
		`sshguard[13689]: Attack from "147.90.234.22" on service SSH with danger 10.`:                                 "147.90.234.22",
		`sshd-session[21342]: Connection closed by invalid user 8.211.47.177 port 36948 [preauth]`:                    "8.211.47.177",
		`sshguard[1]: Blocking "2001:db8::20/128" for 86400 secs`:                                                     "2001:db8::20",
		`sshguard[1]: Blocking "192.0.2.0/24" for 86400 secs`:                                                         "",
	}
	for raw, want := range cases {
		if got := pfsenseSSHSource(raw); got != want {
			t.Fatalf("%s: %s != %s", raw, got, want)
		}
	}
	if pfsenseSSHSource(`application: Attack from "147.90.234.22"`) != "" {
		t.Fatal("unrelated program")
	}
	if sourceIP(`sshguard[1]: Blocking "147.90.234.22/32" for 86400 secs`, "proxmox") != "" {
		t.Fatal("pf parser leaked to proxmox")
	}
}

func TestPFSenseSSHRequiresRepeatedSameIPWithinMinute(t *testing.T) {
	a := testApp(t)
	a.state.Rules = []Rule{pfsenseGuardRule()}
	d := Device{Name: "Firewall", IP: "100.83.245.103", Kind: "pfsense"}
	base := time.Now()
	attempt := func(ip string, when time.Time) {
		raw := fmt.Sprintf("sshd[1]: Invalid user test from %s port 30000", ip)
		a.evaluateRules(Event{ID: token(), Time: when, Device: d.Name, Kind: d.Kind, SourceIP: sourceIP(raw, d.Kind), Message: raw}, raw, d)
	}
	for i := 0; i < 4; i++ {
		attempt("147.90.234.22", base.Add(time.Duration(i)*time.Second))
	}
	attempt("8.211.47.177", base.Add(5*time.Second))
	if len(a.state.Blocks) != 0 {
		t.Fatal("blocked before same-IP threshold")
	}
	attempt("147.90.234.22", base.Add(6*time.Second))
	if _, ok := a.state.Blocks["147.90.234.22"]; !ok {
		t.Fatal("missing threshold block")
	}
	if _, ok := a.state.Blocks["8.211.47.177"]; ok {
		t.Fatal("mixed IPs")
	}
	b := testApp(t)
	b.state.Rules = []Rule{pfsenseGuardRule()}
	for i := 0; i < 5; i++ {
		raw := "sshd[1]: Failed password for invalid user test from 147.90.234.22 port 30000"
		b.evaluateRules(Event{Time: base.Add(time.Duration(i) * 61 * time.Second), SourceIP: "147.90.234.22", Kind: "pfsense"}, raw, d)
	}
	if len(b.state.Blocks) != 0 {
		t.Fatal("old attempts retained")
	}
}
