package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"golang.org/x/crypto/ssh"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTenantScopeIsEnforcedBeforeHistoryReportAndSnapshot(t *testing.T) {
	a := testApp(t)
	global := false
	a.cfg.AllowedEmails = append(a.cfg.AllowedEmails, "b@example.com")
	a.cfg.Devices = []Device{{Name: "A-device", IP: "100.64.0.10", Kind: "linux", Client: "A"}, {Name: "B-device", IP: "100.64.0.11", Kind: "linux", Client: "B"}}
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupAdministrative, Role: "admin", GlobalAccess: &global, Clients: []string{"A"}}, "b@example.com": {Group: groupAdministrative, Role: "admin", GlobalAccess: &global, Clients: []string{"B"}}}
	now := time.Now().UTC().Add(-time.Second)
	for _, e := range []Event{{Tenant: "A", ID: "a", Time: now, Device: "A-device", SenderIP: "100.64.0.10", Message: "A-only"}, {Tenant: "B", ID: "b", Time: now, Device: "B-device", SenderIP: "100.64.0.11", Message: "B-secret"}, {ID: "legacy", Time: now, Message: "Unassigned-secret"}} {
		if !a.appendEvent(e) {
			t.Fatal("fixture")
		}
	}
	for _, path := range []string{"/api/snapshot", "/api/events/history", "/api/events/history?client=B", "/api/reports?start=" + now.Format("2006-01-02") + "&end=" + now.Format("2006-01-02")} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", path, nil))
		if w.Code != 200 || strings.Contains(w.Body.String(), "B-secret") || strings.Contains(w.Body.String(), "Unassigned-secret") {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/api/export", "/api/accounts", "/api/network", "/api/ssh/equipment", "/api/backups"} {
		w := httptest.NewRecorder()
		a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", path, nil))
		if w.Code >= 200 && w.Code < 300 {
			t.Fatal("unsafe global route", path, w.Code)
		}
	}
	request := featureRequest(a, "admin@gmail.com", "GET", "/api/events/history", nil)
	events, _, _, err := a.historyEvents(scopedTestRequest(a, request), 0, "b")
	if err != nil || len(events) != 0 {
		t.Fatal("cross-tenant ID resolved", err)
	}
	// Renaming the current assignment cannot relabel previously collected evidence.
	a.cfg.Devices[1].Client = "A"
	scope := a.requestScope(request)
	if scope.event(Event{Tenant: "B", ID: "b"}) {
		t.Fatal("device reassignment relabeled evidence")
	}
}
func TestTenantNotificationReadCannotAcknowledgeOtherClient(t *testing.T) {
	a := testApp(t)
	global := false
	a.state.Accounts = map[string]AccessAccount{"admin@gmail.com": {Group: groupSuperadmin, Role: "admin", GlobalAccess: &global, Clients: []string{"A"}}}
	a.state.Notifications = []SystemNotification{{ID: "a", Tenant: "A", Time: time.Now()}, {ID: "b", Tenant: "B", Title: "B-hidden", Time: time.Now()}, {ID: "host", Title: "host-private", Time: time.Now()}}
	w := httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "GET", "/api/notifications", nil))
	if strings.Contains(w.Body.String(), "B-hidden") || strings.Contains(w.Body.String(), "host-private") {
		t.Fatal(w.Body.String())
	}
	w = httptest.NewRecorder()
	a.routes().ServeHTTP(w, featureRequest(a, "admin@gmail.com", "POST", "/api/notifications/b/read", []byte(`{}`)))
	if w.Code != 404 {
		t.Fatal("cross-tenant acknowledgement", w.Code)
	}
}
func TestRecoveryRevokesOnlyTargetMFAAndDesktopLinks(t *testing.T) {
	state := State{MFA: map[string]MFARecord{"a@example.com": {EncryptedSecret: "a"}, "b@example.com": {EncryptedSecret: "b"}}, DesktopGrants: map[string]DesktopGrant{"a": {Owner: "a@example.com"}, "b": {Owner: "b@example.com"}}}
	if resetMFARecord(&state, "a@example.com") != nil {
		t.Fatal("reset")
	}
	if len(state.MFA) != 1 || len(state.DesktopGrants) != 1 || state.DesktopGrants["b"].Owner == "" || len(state.Audit) != 1 {
		t.Fatal("reset affected other account")
	}
}
func TestSSHCertificateHasRootControlledScopeAndExpiry(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	ca, _ := ssh.NewSignerFromKey(private)
	_, ephemeral, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(ephemeral)
	now := time.Now()
	req := sshSignRequest{ID: token(), Owner: "operator@example.com", Target: "100.64.0.10", Time: now, PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))}
	policy := sshCAPolicy{Targets: []string{req.Target}, Sources: []string{"100.64.0.20"}}
	cert, err := signSSHRequest(req, policy, ca, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "multipla-ops@100.64.0.10" || cert.ValidBefore-uint64(now.Unix()) != 300 || cert.CriticalOptions["source-address"] != "100.64.0.20/32" {
		t.Fatal("scope/expiry", cert)
	}
	for _, cap := range []string{"permit-port-forwarding", "permit-agent-forwarding", "permit-X11-forwarding"} {
		if _, ok := cert.Extensions[cap]; ok {
			t.Fatal("excess capability", cap)
		}
	}
	req.Target = "100.64.0.99"
	if _, err = signSSHRequest(req, policy, ca, now); err == nil {
		t.Fatal("unapproved target signed")
	}
	req.Target = policy.Targets[0]
	req.Time = now.Add(-time.Minute)
	if _, err = signSSHRequest(req, policy, ca, now); err == nil {
		t.Fatal("expired request signed")
	}
}
func TestDirectIsolationRejectsForwardedAndUntrustedLogs(t *testing.T) {
	policy := isolationPolicy{Peers: []string{"100.64.0.10"}, Local: []string{"100.64.0.20"}, Protected: []string{"100.64.0.99/32"}}
	row := map[string]string{"_TRANSPORT": "kernel", "MESSAGE": "MULTIPLA_DIRECT IN=tailscale0 SRC=100.64.0.10 DST=100.64.0.20 SPT=40100 DPT=22"}
	raw, _ := json.Marshal(row)
	if _, ok := trustedDirectPacket(raw, policy); !ok {
		t.Fatal("direct evidence rejected")
	}
	for _, change := range []map[string]string{{"_TRANSPORT": "syslog"}, {"MESSAGE": "pfSense: MULTIPLA_DIRECT IN=tailscale0 SRC=100.64.0.10 DST=100.64.0.20 SPT=40100 DPT=22"}, {"MESSAGE": "MULTIPLA_DIRECT IN=eth0 SRC=100.64.0.10 DST=100.64.0.20 SPT=40100 DPT=22"}, {"MESSAGE": "MULTIPLA_DIRECT IN=tailscale0 SRC=100.64.0.99 DST=100.64.0.20 SPT=40100 DPT=22"}, {"MESSAGE": "MULTIPLA_DIRECT IN=tailscale0 SRC=100.64.0.10 DST=100.64.0.30 SPT=40100 DPT=22"}, {"MESSAGE": "MULTIPLA_DIRECT IN=tailscale0 SRC=100.64.0.10 DST=100.64.0.20 SPT=40100 DPT=5514"}} {
		copy := map[string]string{}
		for k, v := range row {
			copy[k] = v
		}
		for k, v := range change {
			copy[k] = v
		}
		raw, _ := json.Marshal(copy)
		if _, ok := trustedDirectPacket(raw, policy); ok {
			t.Fatal("untrusted packet accepted", copy)
		}
	}
}

func TestIsolationNotificationIsPersistentAndCannotBeDemoted(t *testing.T) {
	a := testApp(t)
	a.cfg.Devices = []Device{{IP: "100.64.0.10", Name: "Peer", Kind: "linux", Client: "A"}}
	block := DirectIsolation{ID: token(), IP: "100.64.0.10", Time: time.Now(), Reason: "Direct scan"}
	done := make(chan struct{})
	go func() { a.acceptIsolationSnapshot(map[string]DirectIsolation{block.IP: block}); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("isolation collector deadlocked")
	}
	if len(a.state.Notifications) != 1 || !a.state.Notifications[0].Continuous || a.state.Notifications[0].Tenant != "A" {
		t.Fatal("continuous scoped notification missing")
	}
	a.acceptIsolationSnapshot(map[string]DirectIsolation{block.IP: block})
	if len(a.events) != 1 {
		t.Fatal("duplicate isolation event")
	}
	a.state.AlertReviews = map[string]AlertReview{block.ID: {Status: "false_positive", Level: 1}}
	event := a.classifiedEvent(a.events[0])
	if event.Level != 15 || !event.Alert {
		t.Fatal("root isolation was demoted")
	}
	restart, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	restart.acceptIsolationSnapshot(map[string]DirectIsolation{block.IP: block})
	if len(restart.events) != 1 {
		t.Fatal("root notice duplicated on restart")
	}
}
func TestProblemsPreserveCriticalNotificationsOutsideGlobalJournal(t *testing.T) {
	a := testApp(t)
	d := Device{Name: "host", IP: "100.64.0.10", Kind: "proxmox", Client: "A"}
	a.cfg.Devices = []Device{d}
	for i := 0; i < 24; i++ {
		a.ingest(d, "kernel panic on host")
	}
	if len(a.state.ProblemGroups) != 1 {
		t.Fatal("repetitions not grouped")
	}
	path := a.repeatPath(problemKey(Event{Tenant: "A", Device: d.Name, SenderIP: d.IP, Kind: d.Kind, Protocol: "syslog", Message: "kernel panic on host"}))
	if _, err := os.Stat(path); err != nil {
		t.Fatal("separate journal absent", err)
	}
	if len(a.state.Notifications) == 0 {
		t.Fatal("critical notifications suppressed")
	}
	groups := []ProblemGroup{}
	for _, g := range a.state.ProblemGroups {
		groups = append(groups, g)
	}
	if groups[0].Tenant != "A" {
		t.Fatal("scope missing")
	}
	if err := a.persist(); err != nil {
		t.Fatal(err)
	}
	restart, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(restart.state.ProblemGroups) != 1 {
		t.Fatal("group lost on restart")
	}
}
func TestDurableSpoolSurvivesRestartAndKeepsCriticalReserve(t *testing.T) {
	a := testApp(t)
	a.cfg.MaxDailyMB = 1
	normal := Event{ID: token(), Time: time.Now().UTC(), SenderIP: "192.168.1.1", Message: strings.Repeat("x", 9000)}
	for i := 0; i < 55; i++ {
		normal.ID = token()
		if !a.appendEvent(normal) {
			t.Fatal("normal evidence lost before spool full")
		}
	}
	entries, _ := os.ReadDir(filepath.Join(a.cfg.DataDir, "spool"))
	if len(entries) == 0 {
		t.Fatal("source quota did not spool")
	}
	critical := normal
	critical.ID = token()
	critical.Alert = true
	critical.Level = 15
	critical.Message = "critical evidence"
	if !a.appendEvent(critical) {
		t.Fatal("critical reserve unavailable")
	}
	raw, _ := os.ReadFile(a.journalPath(critical.Time))
	if !strings.Contains(string(raw), critical.ID) {
		t.Fatal("critical did not use journal reserve")
	}
	restart, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	entriesAfter, _ := os.ReadDir(filepath.Join(restart.cfg.DataDir, "spool"))
	if len(entriesAfter) != len(entries) {
		t.Fatal("spool lost on restart")
	}
}
