package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
)

func protocolKey(t *testing.T) {
	t.Helper()
	sum := sha256.Sum256([]byte(token()))
	t.Setenv("BACKUP_ENCRYPTION_KEY", hex.EncodeToString(sum[:]))
}

func TestCEFParsingEscapesSeverityAndMalformed(t *testing.T) {
	raw := `<134>Oct 4 UDM CEF:0|Ubiquiti|UniFi Network|9.3|201|Threat \| blocked|7|UNIFIcategory=Security src=198.51.100.42 dst=192.168.10.2 msg=example`
	event, ok := parseCEF(raw)
	if !ok || event.Name != "Threat | blocked" || event.Source != "198.51.100.42" || event.Category != "Security" || event.Destination != "192.168.10.2" {
		t.Fatalf("CEF parse: %+v %v", event, ok)
	}
	if _, level := cefAlert(event); level != 12 {
		t.Fatal("severity mapping")
	}
	for _, raw := range []string{"CEF:0|broken", strings.Replace(raw, "|7|", "|99|", 1), strings.Repeat("x", 513) + raw} {
		if _, ok := parseCEF(raw); ok {
			t.Fatal("malformed accepted")
		}
	}
	event, ok = parseCEF(strings.Replace(raw, "|7|", "|High|", 1))
	if !ok || event.Severity != 8 {
		t.Fatal("textual CEF severity")
	}
}

func TestUniFiAlertsStructuredAndNeverBlock(t *testing.T) {
	a := testApp(t)
	a.cfg.AutoBlock = true
	device := Device{Name: "UDM Pro", IP: "192.168.10.1", Kind: "unifi"}
	raw := `CEF:0|Ubiquiti|UniFi Network|9.3|201|Threat Detected and Blocked|7|UNIFIcategory=Security src=198.51.100.42 msg=Failed password from 198.51.100.42 password=hidden-secret`
	for i := 0; i < 6; i++ {
		a.ingest(device, raw)
	}
	found := false
	for _, event := range a.events {
		if event.Alert && event.Detector == "cef" && event.CEF != nil {
			found = true
			if event.CEF.Source != "198.51.100.42" || strings.Contains(event.Message, "hidden-secret") {
				t.Fatal("structured source or redaction")
			}
		}
	}
	if !found || len(a.state.Blocks) != 0 {
		t.Fatal("missing alert or CEF triggered firewall")
	}
}

func snmpFixture(t *testing.T, version string) (SNMPSource, []byte) {
	t.Helper()
	source := SNMPSource{Name: "Switch SNMP", IP: "192.168.20.10", Version: version, User: "monitor", EngineID: "800000000102030405"}
	credential, err := sealDriveToken("snmp:"+source.IP, DriveToken{Access: "community-secret-2026", Refresh: "authentication-password-2026", Scope: "privacy-password-2026"})
	if err != nil {
		t.Fatal(err)
	}
	source.Credentials = credential
	packet := &gosnmp.SnmpPacket{Version: gosnmp.Version2c, Community: "community-secret-2026", PDUType: gosnmp.SNMPv2Trap, RequestID: 42, Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.2.1.1.3.0", Type: gosnmp.TimeTicks, Value: uint32(100)}, {Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"}, {Name: ".1.3.6.1.2.1.2.2.1.1.0", Type: gosnmp.Integer, Value: 2}}}
	if version == "v3" {
		engine, _ := hex.DecodeString(source.EngineID)
		security := &gosnmp.UsmSecurityParameters{UserName: source.User, AuthoritativeEngineID: string(engine), AuthoritativeEngineBoots: 1, AuthoritativeEngineTime: 100, AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: "authentication-password-2026", PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: "privacy-password-2026"}
		packet.Version = gosnmp.Version3
		packet.MsgFlags = gosnmp.AuthPriv
		packet.SecurityModel = gosnmp.UserSecurityModel
		packet.SecurityParameters = security
		packet.MsgID = 42
		packet.MsgMaxSize = 8192
		if err := security.InitSecurityKeys(); err != nil {
			t.Fatal(err)
		}
		if err := security.InitPacket(packet); err != nil {
			t.Fatal(err)
		}
	}
	data, err := packet.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	return source, data
}

func TestSNMPv2CommunityACLAndNotifications(t *testing.T) {
	protocolKey(t)
	a := testApp(t)
	source, data := snmpFixture(t, "v2c")
	a.state.Receivers = ReceiverSettings{SNMPEnabled: true, Sources: []SNMPSource{source}}
	if a.receiveTrap("192.168.20.11", data) {
		t.Fatal("foreign IP accepted")
	}
	if !a.receiveTrap(source.IP, data) {
		t.Fatal("valid trap rejected")
	}
	if a.receiveTrap(source.IP, data) {
		t.Fatal("duplicate accepted")
	}
	found := false
	for _, event := range a.events {
		if event.Alert && event.Kind == "snmp" && event.Level == 10 {
			found = true
		}
	}
	if !found {
		t.Fatal("linkDown alert missing")
	}
	decoder, err := newSNMPDecoder(source)
	if err != nil {
		t.Fatal(err)
	}
	decoder.Community = "other-community"
	if _, err := decodeTrap(decoder, data); err == nil {
		t.Fatal("wrong community accepted")
	}
}

func TestSNMPv3AuthPrivTamperAndPersistentReplay(t *testing.T) {
	protocolKey(t)
	a := testApp(t)
	source, data := snmpFixture(t, "v3")
	a.state.Receivers = ReceiverSettings{SNMPEnabled: true, Sources: []SNMPSource{source}}
	if !a.receiveTrap(source.IP, data) {
		t.Fatal("valid authPriv trap rejected")
	}
	modified := append([]byte(nil), data...)
	modified[len(modified)-1] ^= 1
	if a.receiveTrap(source.IP, modified) {
		t.Fatal("tampered trap accepted")
	}
	restarted, err := newApp(a.cfg, a.configPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.receiveTrap(source.IP, data) {
		t.Fatal("replayed trap accepted after restart")
	}
	source.User = "intruder"
	decoder, err := newSNMPDecoder(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTrap(decoder, data); err == nil {
		t.Fatal("wrong v3 username accepted")
	}
}

func TestSNMPv3TimelinessRejectsOldBootAndClock(t *testing.T) {
	protocolKey(t)
	a := testApp(t)
	source, data := snmpFixture(t, "v3")
	decoder, _ := newSNMPDecoder(source)
	packet, err := decodeTrap(decoder, data)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	a.state.SNMPClocks[source.IP] = SNMPClock{EngineID: source.EngineID, Boots: 2, Ticks: 100, At: now}
	if a.acceptTrapClock(source, packet, data, now) {
		t.Fatal("previous engine boot accepted")
	}
	a.state.SNMPClocks[source.IP] = SNMPClock{EngineID: source.EngineID, Boots: 1, Ticks: 1000, At: now}
	if a.acceptTrapClock(source, packet, data, now) {
		t.Fatal("stale engine time accepted")
	}
}

func TestWebhookTargetsRejectSSRF(t *testing.T) {
	for _, target := range []string{"http://example.com/hook", "https://127.0.0.1/hook", "https://169.254.169.254/latest", "https://[::1]/hook", "https://100.100.100.200/hook", "https://user:pass@example.com/hook", "https://example.com/hook?token=secret"} {
		if validateWebhookURL(target, "") == nil {
			t.Fatalf("unsafe URL accepted: %s", target)
		}
	}
	if validateWebhookURL("https://192.168.10.20/hook", "") == nil {
		t.Fatal("private destination implicit")
	}
	if err := validateWebhookURL("https://192.168.10.20/hook", "192.168.10.20"); err != nil {
		t.Fatal(err)
	}
	if webhookIPAllowed(netip.MustParseAddr("::ffff:127.0.0.1"), "") {
		t.Fatal("mapped localhost accepted")
	}
	if err := validateWebhookURL("https://alerts.example.com/hook", ""); err != nil {
		t.Fatal(err)
	}
}

func TestInboundWebhookTokenSourceValidationAndQueue(t *testing.T) {
	protocolKey(t)
	a := testApp(t)
	cipher, err := sealDriveToken("webhook-in", DriveToken{Access: "private-webhook-input-token"})
	if err != nil {
		t.Fatal(err)
	}
	a.state.Receivers = ReceiverSettings{InboundEnabled: true, InboundIPs: []string{"192.168.10.20"}, InboundCredentials: cipher, OutboundEnabled: true, OutboundURL: "https://alerts.example.com/hook", OutboundLevel: 10}
	for _, test := range []struct {
		peer, token, body string
		status            int
	}{{"192.168.10.21", "private-webhook-input-token", `{"message":"test","level":12}`, 403}, {"192.168.10.20", "wrong", `{"message":"test","level":12}`, 403}, {"192.168.10.20", "private-webhook-input-token", `{"message":"test","level":99}`, 400}, {"192.168.10.20", "private-webhook-input-token", `{"message":"password=hidden-secret","title":"Critical hardware","level":12}`, 200}} {
		req := httptest.NewRequest("POST", a.origin+"/api/events/webhook", strings.NewReader(test.body))
		req.RemoteAddr = test.peer + ":23456"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+test.token)
		response := httptest.NewRecorder()
		a.routes().ServeHTTP(response, req)
		if response.Code != test.status {
			t.Fatalf("webhook: %d %s", response.Code, response.Body.String())
		}
	}
	if len(a.webhookQ) != 1 || len(a.mailQ) != 1 || len(a.state.Blocks) != 0 {
		t.Fatal("notification queue or firewall isolation")
	}
	event := <-a.webhookQ
	body := string(webhookBody(event))
	if strings.Contains(body, "hidden-secret") || strings.Contains(body, "password") {
		t.Fatal("raw log leaked in notification")
	}
}

func TestReceiverConfigurationSecretsExcludedAndRestorePaused(t *testing.T) {
	protocolKey(t)
	a := testApp(t)
	source, _ := snmpFixture(t, "v3")
	a.state.Receivers = ReceiverSettings{SNMPEnabled: true, Sources: []SNMPSource{source}, OutboundURL: "https://alerts.example.com/private-path-token"}
	backup := a.backupDocument("admin@gmail.com")
	data, _ := json.Marshal(backup)
	if strings.Contains(string(data), source.Credentials) || strings.Contains(string(data), "private-path-token") {
		t.Fatal("receiver credential or secret URL exported")
	}
	if err := a.restoreBackup("admin@gmail.com", data); err != nil {
		t.Fatal(err)
	}
	if a.state.Receivers.SNMPEnabled || a.state.Receivers.OutboundEnabled || a.state.Receivers.Sources[0].Credentials != source.Credentials {
		t.Fatal("restore did not pause or preserve private credentials")
	}
	backup.Receivers.Sources[0].Credentials = "injected"
	data, _ = json.Marshal(backup)
	if _, err := decodeBackup(data); err == nil {
		t.Fatal("credentials injected through import")
	}
}

func TestNewReceiverRoutesPrivateAndCSRF(t *testing.T) {
	a := testApp(t)
	for _, path := range []string{"/api/receivers", "/api/receivers/snmp", "/api/receivers/webhook"} {
		method := "GET"
		if path != "/api/receivers" {
			method = "PUT"
		}
		req := httptest.NewRequest(method, a.origin+path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		a.routes().ServeHTTP(response, req)
		if response.Code != 401 {
			t.Fatal(path, response.Code)
		}
	}
	a.sessions["admin"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	req := httptest.NewRequest("PUT", a.origin+"/api/receivers/snmp", strings.NewReader(`{"enabled":false,"sources":[]}`))
	req.Header.Set("Origin", a.origin)
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "admin"})
	response := httptest.NewRecorder()
	a.routes().ServeHTTP(response, req)
	if response.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
}

func FuzzCEFAndSNMPParsing(f *testing.F) {
	f.Add([]byte("CEF:0|Ubiquiti|UniFi Network|9|201|Threat|7|src=198.51.100.42"))
	f.Add([]byte{0x30, 0x82, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 16384 {
			return
		}
		parseCEF(string(data))
		decoder := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: "test-community-2026"}
		decodeTrap(decoder, data)
	})
}

func TestOutboundWebhookSignatureMinimalPayloadAndRedirectPolicy(t *testing.T) {
	protocolKey(t)
	secret := "abcdefghijklmnopqrstuvwxyz0123456789"
	encrypted, err := sealDriveToken("webhook-out", DriveToken{Access: secret})
	if err != nil {
		t.Fatal(err)
	}
	settings := ReceiverSettings{OutboundURL: "https://alerts.example.com/hook", OutboundCredentials: encrypted}
	event := Event{ID: token(), Time: time.Now().UTC(), Protocol: "snmp", Device: "Switch", Rule: "SNMP linkDown", Level: 12, Alert: true, Message: "private raw log should stay local"}
	observed := false
	sender := &http.Client{Transport: roundTrip(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		if request.Method != "POST" || request.URL.Host != "alerts.example.com" || request.Header.Get("X-Multipla-Event-ID") != event.ID {
			t.Fatal("delivery identity")
		}
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(request.Header.Get("X-Multipla-Timestamp") + "."))
		mac.Write(body)
		if request.Header.Get("X-Multipla-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
			t.Fatal("signature mismatch")
		}
		if strings.Contains(string(body), secret) || strings.Contains(string(body), "private raw log") {
			t.Fatal("secret/raw payload leaked")
		}
		observed = true
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
	})}
	if err := deliverWebhookHTTP(context.Background(), settings, event, sender); err != nil || !observed {
		t.Fatal("not delivered", err)
	}
	secure := webhookClient("")
	if secure.CheckRedirect(nil, nil) == nil {
		t.Fatal("redirect allowed")
	}
}

func TestWebhookDNSRejectsMixedPublicPrivateResults(t *testing.T) {
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	if _, err := resolveWebhookDestination(context.Background(), "alerts.example.com", "", lookup); err == nil {
		t.Fatal("mixed DNS accepted")
	}
	calls := 0
	lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		calls++
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	ips, err := resolveWebhookDestination(context.Background(), "alerts.example.com", "", lookup)
	if err != nil || calls != 1 || ips[0].String() != "8.8.8.8" {
		t.Fatal("destination not resolved once")
	}
}

func TestReceiverSettingsGETDoesNotReturnSecrets(t *testing.T) {
	protocolKey(t)
	a := testApp(t)
	source, _ := snmpFixture(t, "v3")
	a.state.Receivers = ReceiverSettings{Sources: []SNMPSource{source}, InboundCredentials: "secret-in", OutboundCredentials: "secret-out"}
	a.sessions["admin"] = Session{Email: "admin@gmail.com", CSRF: "csrf", Expires: time.Now().Add(time.Hour)}
	request := httptest.NewRequest("GET", a.origin+"/api/receivers", nil)
	request.AddCookie(&http.Cookie{Name: a.sessionName(), Value: "admin"})
	response := httptest.NewRecorder()
	a.routes().ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatal(response.Code)
	}
	for _, secret := range []string{source.Credentials, "secret-in", "secret-out"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("secret returned")
		}
	}
}

func TestWebhookQueueThresholdAndDiskFailure(t *testing.T) {
	a := testApp(t)
	a.state.Receivers = ReceiverSettings{OutboundEnabled: true, OutboundLevel: 12}
	a.queueWebhook(Event{Alert: true, Level: 11})
	if len(a.webhookQ) != 0 {
		t.Fatal("threshold ignored")
	}
	a.queueWebhook(Event{Alert: true, Level: 12})
	if len(a.webhookQ) != 1 {
		t.Fatal("alert not queued")
	}
	<-a.webhookQ
	a.cfg.DataDir = "\x00"
	if a.appendEvent(Event{ID: token(), Time: time.Now().UTC(), Alert: true, Level: 12}) || len(a.webhookQ) != 0 {
		t.Fatal("disk failure produced webhook")
	}
}

func TestSNMPv3UDPReception(t *testing.T) {
	protocolKey(t)
	a := testApp(t)
	source, data := snmpFixture(t, "v3")
	source.IP = "127.0.0.1"
	cipher, err := sealDriveToken("snmp:"+source.IP, DriveToken{Access: "community-secret-2026", Refresh: "authentication-password-2026", Scope: "privacy-password-2026"})
	if err != nil {
		t.Fatal(err)
	}
	source.Credentials = cipher
	a.state.Receivers = ReceiverSettings{SNMPEnabled: true, Sources: []SNMPSource{source}}
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { a.serveSNMPSocket(socket); close(done) }()
	defer func() { socket.Close(); <-done }()
	sender, err := net.Dial("udp", socket.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	if _, err = sender.Write(data); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.mu.Lock()
		found := false
		for _, event := range a.events {
			if event.Alert && event.Kind == "snmp" {
				found = true
			}
		}
		a.mu.Unlock()
		if found {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("UDP trap not received")
}

func TestSNMPv3RejectsUnauthenticatedDowngrade(t *testing.T) {
	protocolKey(t)
	source, _ := snmpFixture(t, "v3")
	engine, _ := hex.DecodeString(source.EngineID)
	packet := &gosnmp.SnmpPacket{Version: gosnmp.Version3, MsgID: 1, MsgMaxSize: 8192, MsgFlags: gosnmp.NoAuthNoPriv, SecurityModel: gosnmp.UserSecurityModel, SecurityParameters: &gosnmp.UsmSecurityParameters{UserName: source.User, AuthoritativeEngineID: string(engine)}, PDUType: gosnmp.SNMPv2Trap, Variables: []gosnmp.SnmpPDU{{Name: ".1.3.6.1.6.3.1.1.4.1.0", Type: gosnmp.ObjectIdentifier, Value: ".1.3.6.1.6.3.1.1.5.3"}}}
	data, err := packet.MarshalMsg()
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := newSNMPDecoder(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeTrap(decoder, data); err == nil {
		t.Fatal("v3 without auth/privacy accepted")
	}
}
