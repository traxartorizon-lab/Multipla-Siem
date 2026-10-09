package main

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

//go:embed web/*
var assets embed.FS

type Device struct {
	MAC       string `json:"mac,omitempty"`
	WOLTarget string `json:"wol_target,omitempty"`
	Client    string `json:"client,omitempty"`
	Unit      string `json:"unit,omitempty"`
	Name      string `json:"name"`
	IP        string `json:"ip"`
	Kind      string `json:"kind"`
}
type Config struct {
	SNMP          string   `json:"snmp"`
	FirstBoot     bool     `json:"first_boot,omitempty"`
	LocalAnalysis bool     `json:"local_analysis"`
	Listen        string   `json:"listen"`
	Syslog        string   `json:"syslog"`
	PublicURL     string   `json:"public_url"`
	DataDir       string   `json:"data_dir"`
	RetentionDays int      `json:"retention_days"`
	AllowedEmails []string `json:"allowed_emails"`
	Devices       []Device `json:"devices"`
	Protected     []string `json:"protected_cidrs"`
	AutoBlock     bool     `json:"auto_block"`
	BlockMinutes  int      `json:"block_minutes"`
	MailTo        string   `json:"mail_to"`
	MailMinLevel  int      `json:"mail_min_level"`
	FeedAllowed   []string `json:"feed_allowed_cidrs"`
	TLSCert       string   `json:"tls_cert"`
	TLSKey        string   `json:"tls_key"`
	MaxDailyMB    int      `json:"max_daily_mb"`
}
type Rule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Pattern   string `json:"pattern"`
	Threshold int    `json:"threshold"`
	Window    int    `json:"window_seconds"`
	Level     int    `json:"level"`
	Block     bool   `json:"block"`
	Enabled   bool   `json:"enabled"`
}
type Event struct {
	Classification *CriticalClassification `json:"classification,omitempty"`
	ParentID       string                  `json:"parent_id,omitempty"`
	Diagnosis      *Diagnosis              `json:"diagnosis,omitempty"`
	Review         *AlertReview            `json:"review,omitempty"`
	ModelDiagnosis *ModelDiagnosis         `json:"model_diagnosis,omitempty"`
	Protocol       string                  `json:"protocol,omitempty"`
	SenderIP       string                  `json:"sender_ip,omitempty"`
	CEF            *CEFEvent               `json:"cef,omitempty"`
	Detector       string                  `json:"detector,omitempty"`
	ID             string                  `json:"id"`
	Time           time.Time               `json:"time"`
	Device         string                  `json:"device"`
	Kind           string                  `json:"kind"`
	SourceIP       string                  `json:"source_ip"`
	Message        string                  `json:"message"`
	Level          int                     `json:"level"`
	Rule           string                  `json:"rule"`
	Alert          bool                    `json:"alert"`
}
type Block struct {
	IP      string    `json:"ip"`
	Expires time.Time `json:"expires"`
	Reason  string    `json:"reason"`
	Mode    string    `json:"mode"`
}
type Audit struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"`
}
type State struct {
	Notifications        []SystemNotification       `json:"notifications,omitempty"`
	NotificationsCleared map[string]time.Time       `json:"notifications_cleared,omitempty"`
	HostConditions       map[string]bool            `json:"host_conditions,omitempty"`
	CriticalPatterns     map[string]CriticalPattern `json:"critical_patterns,omitempty"`
	N8N                  N8NSettings                `json:"n8n,omitempty"`
	N8NOutbox            []N8NDelivery              `json:"n8n_outbox,omitempty"`
	MetricKeys           map[string]string          `json:"metric_keys,omitempty"`
	DeviceMetrics        map[string]DeviceTelemetry `json:"device_metrics,omitempty"`
	TemporaryReports     []TemporaryReport          `json:"temporary_reports,omitempty"`
	PFSourceMigration    bool                       `json:"pf_source_migration,omitempty"`
	SSHHostKeys          map[string]SSHHostIdentity `json:"ssh_host_keys,omitempty"`
	NetworkEquipment     []NetworkEquipment         `json:"network_equipment,omitempty"`
	AlertReviews         map[string]AlertReview     `json:"alert_reviews,omitempty"`
	InternetAnalysis     bool                       `json:"internet_analysis,omitempty"`
	OllamaLegacyCleaned  bool                       `json:"ollama_legacy_cleaned,omitempty"`
	LocalAIModel         string                     `json:"local_ai_model,omitempty"`
	ModelDiagnoses       map[string]ModelDiagnosis  `json:"model_diagnoses,omitempty"`
	Accounts             map[string]AccessAccount   `json:"accounts,omitempty"`
	Receivers            ReceiverSettings           `json:"receivers"`
	SNMPClocks           map[string]SNMPClock       `json:"snmp_clocks,omitempty"`
	GoogleSettings       string                     `json:"google_settings_encrypted,omitempty"`
	LocalAdmin           LocalAdmin                 `json:"local_admin,omitempty"`
	GoogleSubjects       map[string]string          `json:"google_subjects,omitempty"`
	Preferences          map[string]Preferences     `json:"preferences,omitempty"`
	BackupStatus         map[string]BackupStatus    `json:"backup_status,omitempty"`
	DriveTokens          map[string]string          `json:"drive_tokens_encrypted,omitempty"`
	Rules                []Rule                     `json:"rules"`
	Blocks               map[string]Block           `json:"blocks"`
	Audit                []Audit                    `json:"audit"`
	BootstrapDigest      string                     `json:"bootstrap_digest,omitempty"`
}
type Session struct {
	Subject string
	Email   string
	CSRF    string
	Expires time.Time
}
type OAuth struct {
	DriveSubject string
	DriveEmail   string
	Verifier     string
	Expires      time.Time
}
type bucket struct {
	Times []time.Time
	Last  time.Time
}
type App struct {
	hostHealth        HostHealth
	hostPrevious      HostCounters
	notificationDirty bool
	resourceHistoryMu sync.Mutex
	n8nTestBusy       bool
	n8nTestLast       time.Time
	sshTerminals      map[string]*sshTerminal
	networkTests      map[string]*NetworkTest
	aiQueue           chan Event
	aiPending         map[string]bool
	aiStatus          localAIStatus
	aiCleanupRunning  bool
	aiCleanupTarget   string
	snmpMu            sync.Mutex
	snmpDecoders      map[string]snmpDecoder
	snmpSeen          map[string]time.Time
	protocolSeen      map[string]time.Time
	webhookQ          chan Event
	webhookStatus     string
	snmpStatus        string
	backupMu          sync.Mutex
	driveMu           sync.Mutex
	analyzer          *localAnalyzer
	mu                sync.Mutex
	cfg               Config
	state             State
	events            []Event
	sessions          map[string]Session
	oauth             map[string]OAuth
	counters          map[string]bucket
	seen              map[string]time.Time
	lastSeen          map[string]time.Time
	devicePresence    map[string]bool
	total             int64
	totalDay          string
	dropped           int64
	storageError      string
	mailStatus        string
	feedSeen          time.Time
	demo              bool
	mailQ             chan Event
	configPath        string
	origin            string
	rates             map[string]rateWindow
	active            map[string]time.Time
	bootAt            time.Time
	bootstrapUsed     bool
	nativeTLS         bool
	localIPs          map[netip.Addr]bool
}

var client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
var ipRE = regexp.MustCompile(`(?:from|rhost=|src=|srcip[=: ]+)\s*([0-9a-fA-F:.]+)`)

func token() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func equal(a, b string) bool {
	return a != "" && b != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func defaults() []Rule {
	return []Rule{
		pfsenseGuardRule(),
		{"ssh-brute", "Tentativas repetidas de acesso", "any", `(?i)(failed password|authentication failure|authentication failed|invalid user)`, 5, 120, 10, true, true},
		{"firewall-burst", "Conexões bloqueadas em sequência", "pfsense", `filterlog:.*`, 30, 60, 8, false, true},
		{"system-failure", "Falha de serviço ou armazenamento", "proxmox", `(?i)(I/O error|out of memory|oom-kill|task.*error|backup.*failed)`, 1, 60, 9, false, true},
	}
}
func validateConfig(c Config) error {
	if c.MaxDailyMB < 0 || c.MaxDailyMB > 8192 {
		return errors.New("limite diário de logs deve ser entre 1 e 8192 MiB; zero usa 256 MiB")
	}
	if c.RetentionDays < 1 || c.RetentionDays > 365 || c.BlockMinutes < 1 || c.BlockMinutes > 10080 || c.MailMinLevel < 1 || c.MailMinLevel > 15 {
		return errors.New("retenção, duração ou nível fora dos limites")
	}
	u, e := url.Parse(c.PublicURL)
	if e != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"))) || u.Path != "" || u.RawQuery != "" || u.User != nil || u.Fragment != "" || u.Opaque != "" {
		return errors.New("public_url deve ser origem HTTPS (HTTP apenas localhost)")
	}
	if _, _, e = net.SplitHostPort(c.Listen); e != nil {
		return e
	}
	if c.SNMP != "" {
		if _, _, err := net.SplitHostPort(c.SNMP); err != nil {
			return err
		}
	}
	if _, _, e = net.SplitHostPort(c.Syslog); e != nil {
		return e
	}
	ips := map[string]bool{}
	names := map[string]bool{}
	for _, d := range c.Devices {
		ip, e := netip.ParseAddr(d.IP)
		if e != nil || ip.String() != d.IP || ips[d.IP] || names[d.Name] || d.Name == "" || len(d.Name) > 80 || strings.ContainsAny(d.Name, "\r\n\x00") || (d.Kind != "linux" && d.Kind != "windows" && d.Kind != "pfsense" && d.Kind != "proxmox" && d.Kind != "generic" && d.Kind != "unifi") {
			return errors.New("dispositivo inválido ou IP duplicado")
		}
		if err := validateDeviceNetwork(d); err != nil {
			return err
		}
		ips[d.IP] = true
		names[d.Name] = true
	}
	if len(c.Devices) > 256 || len(c.Protected) > 256 || len(c.FeedAllowed) > 256 || len(c.AllowedEmails) > 100 {
		return errors.New("limite de configuração excedido")
	}
	for _, p := range append(append([]string(nil), c.Protected...), c.FeedAllowed...) {
		if _, e := netip.ParsePrefix(p); e != nil {
			return e
		}
	}
	for _, s := range c.AllowedEmails {
		a, e := mail.ParseAddress(s)
		if e != nil || a.Address != s {
			return errors.New("email autorizado inválido")
		}
	}
	if c.MailTo != "" {
		a, e := mail.ParseAddress(c.MailTo)
		if e != nil || a.Address != c.MailTo {
			return errors.New("destinatário inválido")
		}
	}
	return nil
}
func atomicJSON(path string, v any) error {
	b, e := json.MarshalIndent(v, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".save-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func newApp(c Config, path string, demo bool) (*App, error) {
	c.LocalAnalysis = true
	if e := validateConfig(c); e != nil {
		return nil, e
	}
	if e := os.MkdirAll(c.DataDir, 0700); e != nil {
		return nil, e
	}
	a := &App{cfg: c, configPath: path, origin: c.PublicURL, demo: demo, state: State{Rules: defaults(), Blocks: map[string]Block{}}, sessions: map[string]Session{}, oauth: map[string]OAuth{}, counters: map[string]bucket{}, seen: map[string]time.Time{}, lastSeen: map[string]time.Time{}, mailQ: make(chan Event, 64)}
	a.rates = map[string]rateWindow{}
	a.aiQueue = make(chan Event, 64)
	a.aiPending = map[string]bool{}
	a.analyzer = newLocalAnalyzer()
	a.webhookQ = make(chan Event, 64)
	a.protocolSeen = map[string]time.Time{}
	a.active = map[string]time.Time{}
	a.bootAt = time.Now()
	a.nativeTLS = c.TLSCert != "" && c.TLSKey != ""
	a.localIPs = map[netip.Addr]bool{}
	if addrs, e := net.InterfaceAddrs(); e == nil {
		for _, addr := range addrs {
			if p, e := netip.ParsePrefix(addr.String()); e == nil {
				a.localIPs[p.Addr().Unmap()] = true
			}
		}
	}
	if u, e := url.Parse(c.PublicURL); e == nil {
		if ip, e := netip.ParseAddr(u.Hostname()); e == nil {
			a.localIPs[ip.Unmap()] = true
		}
	}
	b, e := os.ReadFile(filepath.Join(c.DataDir, "state.json"))
	if e == nil {
		if e = json.Unmarshal(b, &a.state); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if err := validateCriticalPatterns(a.state.CriticalPatterns); err != nil {
		return nil, err
	}
	if !a.state.PFSourceMigration {
		found := false
		for _, rule := range a.state.Rules {
			if rule.ID == "pfsense-sshguard" {
				found = true
			}
		}
		if !found {
			a.state.Rules = append(a.state.Rules, pfsenseGuardRule())
		}
		a.state.PFSourceMigration = true
		if e == nil {
			if err := a.persist(); err != nil {
				return nil, err
			}
		}
	}
	if a.state.GoogleSettings != "" {
		if settings, err := openDriveToken("multipla-oauth-config", a.state.GoogleSettings); err == nil {
			googleRedaction.Store(&settings.Refresh)
		}
	}
	if a.state.SNMPClocks == nil {
		a.state.SNMPClocks = map[string]SNMPClock{}
	}
	for _, clock := range a.state.SNMPClocks {
		if len(clock.History) > 128 {
			return nil, errors.New("histórico SNMP excedido")
		}
	}
	if len(a.state.SNMPClocks) > 64 {
		return nil, errors.New("limite de relógios SNMP excedido")
	}
	if err := validateReceivers(a.state.Receivers); err != nil {
		return nil, err
	}
	if err := validateN8N(a.state.N8N); err != nil {
		return nil, err
	}
	if len(a.state.N8NOutbox) > n8nQueueLimit {
		return nil, errors.New("fila n8n excedida")
	}
	a.receiverSecrets()
	if a.state.GoogleSubjects == nil {
		a.state.GoogleSubjects = map[string]string{}
	}
	if len(a.state.GoogleSubjects) > 102 {
		return nil, errors.New("limite de identidades excedido")
	}
	if a.state.Preferences == nil {
		a.state.Preferences = map[string]Preferences{}
	}
	if a.state.BackupStatus == nil {
		a.state.BackupStatus = map[string]BackupStatus{}
	}
	if a.state.DriveTokens == nil {
		a.state.DriveTokens = map[string]string{}
	}
	if len(a.state.Preferences) > 102 || len(a.state.DriveTokens) > 102 || len(a.state.BackupStatus) > 102 {
		return nil, errors.New("limite de contas persistidas excedido")
	}
	for _, p := range a.state.Preferences {
		if e := validatePreferences(p); e != nil {
			return nil, e
		}
	}
	if a.state.Blocks == nil {
		a.state.Blocks = map[string]Block{}
	}
	for i := range a.state.Audit {
		a.state.Audit[i].Actor = redact(a.state.Audit[i].Actor)
		a.state.Audit[i].Action = redact(a.state.Audit[i].Action)
	}
	for ip, b := range a.state.Blocks {
		b.Reason = redact(b.Reason)
		a.state.Blocks[ip] = b
	}
	if e = validateRules(a.state.Rules); e != nil {
		return nil, e
	}
	// Replay only the current day's bounded dashboard window; older days stay searchable on disk.
	f, e := os.Open(a.journalPath(time.Now()))
	if e == nil {
		defer f.Close()
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 65536), 262144)
		for s.Scan() {
			var ev Event
			if json.Unmarshal(s.Bytes(), &ev) == nil {
				a.remember(ev)
			}
		}
		if e = s.Err(); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	return a, nil
}
func (a *App) journalPath(t time.Time) string {
	return filepath.Join(a.cfg.DataDir, "events-"+t.UTC().Format("2006-01-02")+".jsonl")
}
func (a *App) remember(e Event) {
	e = sanitizeEvent(e)
	a.events = append(a.events, e)
	if len(a.events) > 2000 {
		a.events = append([]Event(nil), a.events[len(a.events)-2000:]...)
	}
	day := e.Time.UTC().Format("2006-01-02")
	if a.totalDay != day {
		a.totalDay = day
		a.total = 0
	}
	if !e.Alert || e.Kind == "wazuh" {
		a.total++
	}
	a.lastSeen[e.Device] = e.Time
}
func (a *App) persist() error { return atomicJSON(filepath.Join(a.cfg.DataDir, "state.json"), a.state) }
func (a *App) audit(actor, action string) {
	a.state.Audit = append(a.state.Audit, Audit{time.Now().UTC(), redact(actor), redact(action)})
	if len(a.state.Audit) > 500 {
		a.state.Audit = a.state.Audit[len(a.state.Audit)-500:]
	}
}
func (a *App) appendEvent(e Event) bool {
	e = sanitizeEvent(e)
	e.Diagnosis = localDiagnosis(e)
	encoded, err := json.Marshal(e)
	if err != nil {
		a.storageError = "Falha de serialização"
		a.dropped++
		return false
	}
	limit := a.cfg.MaxDailyMB
	if limit == 0 {
		limit = 256
	}
	path := a.journalPath(e.Time)
	size := int64(0)
	if st, e := os.Stat(path); e == nil {
		size = st.Size()
	}
	if size+int64(len(encoded)+1) > int64(limit)*1024*1024 {
		a.storageError = "Limite diário de logs atingido; aumente o limite ou investigue o volume"
		a.dropped++
		return false
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		_, err = f.Write(append(encoded, '\n'))
		ce := f.Close()
		if err == nil {
			err = ce
		}
	}
	if err != nil {
		a.storageError = err.Error()
		a.dropped++
		log.Printf("journal: %v", err)
		return false
	}
	a.storageError = ""
	a.remember(e)
	a.enqueueLocalAI(e)
	a.notifyCriticalEvent(a.classifiedEvent(e))
	a.queueWebhook(a.classifiedEvent(e))
	a.queueN8N(a.classifiedEvent(e))
	return true
}
func sourceIP(raw, kind string) string {
	if kind == "pfsense" {
		if ip := pfsenseSSHSource(raw); ip != "" {
			return ip
		}
		if i := strings.Index(raw, "filterlog:"); i >= 0 {
			f := strings.Split(strings.TrimSpace(raw[i+10:]), ",")
			if len(f) > 19 && f[8] == "4" && f[6] == "block" {
				if ip, e := netip.ParseAddr(f[18]); e == nil {
					return ip.Unmap().String()
				}
			}
			if len(f) > 16 && f[8] == "6" && f[6] == "block" {
				if ip, e := netip.ParseAddr(f[15]); e == nil {
					return ip.String()
				}
			}
			return ""
		}
	}
	m := ipRE.FindStringSubmatch(raw)
	if len(m) > 1 {
		if ip, e := netip.ParseAddr(strings.TrimRight(m[1], ".")); e == nil {
			return ip.Unmap().String()
		}
	}
	return ""
}
func (a *App) protected(ip netip.Addr) bool {
	if a.localIPs[ip.Unmap()] {
		return true
	}
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	for _, s := range a.cfg.Protected {
		p, _ := netip.ParsePrefix(s)
		if p.Contains(ip) {
			return true
		}
	}
	for _, d := range a.cfg.Devices {
		p, _ := netip.ParseAddr(d.IP)
		if p == ip {
			return true
		}
	}
	for _, source := range a.state.Receivers.Sources {
		if source.IP == ip.String() {
			return true
		}
	}
	for _, peer := range a.state.Receivers.InboundIPs {
		if peer == ip.String() {
			return true
		}
	}
	return false
}
func (a *App) block(ipText, reason, actor string) error {
	ip, e := netip.ParseAddr(ipText)
	if e != nil || a.protected(ip.Unmap()) {
		return errors.New("IP inválido ou protegido")
	}
	ipText = ip.Unmap().String()
	if len(a.state.Blocks) >= 4096 {
		if _, ok := a.state.Blocks[ipText]; !ok {
			return errors.New("limite de bloqueios atingido")
		}
	}
	mode := "simulation"
	if a.cfg.AutoBlock && !a.demo {
		mode = "published"
	}
	old, had := a.state.Blocks[ipText]
	oldAudit := append([]Audit(nil), a.state.Audit...)
	a.state.Blocks[ipText] = Block{ipText, time.Now().Add(time.Duration(a.cfg.BlockMinutes) * time.Minute), redact(reason), mode}
	a.audit(actor, "bloqueio "+mode+" "+ipText+": "+reason)
	if e = a.persist(); e != nil {
		if had {
			a.state.Blocks[ipText] = old
		} else {
			delete(a.state.Blocks, ipText)
		}
		a.state.Audit = oldAudit
		return e
	}
	return nil
}
func (a *App) ingest(d Device, raw string) {
	if len(raw) > 16384 {
		raw = raw[:16384]
	}
	now := time.Now().UTC()
	a.mu.Lock()
	defer a.mu.Unlock()
	ev := Event{ID: token(), Time: now, Device: d.Name, Kind: d.Kind, Protocol: "syslog", SenderIP: d.IP, SourceIP: sourceIP(raw, d.Kind), Message: redact(raw)}
	title, level := "", 0
	if cef, ok := parseCEF(raw); ok {
		ev.CEF = &cef
		ev.Detector = "cef"
		ev.SourceIP = cef.Source
		title, level = cefAlert(cef)
	}
	if d.Kind == "snmp" {
		ev.Protocol = "snmp"
		ev.Detector = "snmp-trap"
		ev.SourceIP = d.IP
		title, level = snmpAlert(raw)
	}
	if !a.appendEvent(ev) {
		return
	}
	a.analyzeEvent(ev)
	if title != "" {
		key := d.Kind + ":" + d.IP + ":" + fmt.Sprint(level)
		if ev.CEF != nil {
			key += ":" + ev.CEF.EventID
		} else {
			key += ":" + title
		}
		for saved, at := range a.protocolSeen {
			if now.Sub(at) > 5*time.Minute {
				delete(a.protocolSeen, saved)
			}
		}
		previous, known := a.protocolSeen[key]
		if (known || len(a.protocolSeen) < 1024) && (previous.IsZero() || now.Sub(previous) >= 30*time.Second) {
			alert := ev
			alert.ID = token()
			alert.ParentID = ev.ID
			alert.Alert = true
			alert.Rule = title
			alert.Level = level
			if a.appendEvent(alert) {
				a.protocolSeen[key] = now
				if level >= a.cfg.MailMinLevel {
					select {
					case a.mailQ <- sanitizeEvent(alert):
					default:
						a.mailStatus = "Fila cheia"
					}
				}
			}
		}
	}
	a.evaluateRules(ev, raw, d)
}

// Caller holds a.mu; protocol alerts never publish firewall blocks.
func (a *App) evaluateRules(ev Event, raw string, d Device) {
	now := ev.Time
	for _, r := range a.state.Rules {
		// The dedicated one-minute pfSense policy replaces the legacy generic SSH rule.
		if d.Kind == "pfsense" && r.ID == "ssh-brute" {
			continue
		}
		if !r.Enabled || (r.Kind != "any" && r.Kind != d.Kind) {
			continue
		}
		re, _ := regexp.Compile(r.Pattern)
		if !re.MatchString(raw) {
			continue
		}
		if (r.ID == "firewall-burst" || r.ID == "pfsense-sshguard") && ev.SourceIP == "" {
			continue
		}
		key := r.ID + "|" + d.IP + "|" + ev.SourceIP
		b := a.counters[key]
		cut := now.Add(-time.Duration(r.Window) * time.Second)
		var ts []time.Time
		for _, t := range b.Times {
			if t.After(cut) {
				ts = append(ts, t)
			}
		}
		if len(ts) < r.Threshold {
			ts = append(ts, now)
		}
		b.Times = ts
		if len(ts) >= r.Threshold && (b.Last.IsZero() || b.Last.Before(cut)) {
			b.Last = now
			alert := ev
			alert.ID = token()
			alert.ParentID = ev.ID
			alert.Alert = true
			alert.Rule = r.Name
			alert.Level = r.Level
			if a.appendEvent(alert) {
				if r.Block && ev.SourceIP != "" && ev.CEF == nil && ev.Kind != "snmp" && ev.Kind != "webhook" {
					if e := a.block(ev.SourceIP, r.Name, "engine"); e != nil {
						log.Printf("block skipped: %v", e)
					}
				}
				if alert.Level >= a.cfg.MailMinLevel {
					select {
					case a.mailQ <- sanitizeEvent(alert):
					default:
						a.mailStatus = "Fila de email cheia; notificação descartada"
					}
				}
			}
		}
		if len(a.counters) < 10000 {
			a.counters[key] = b
		} else if _, ok := a.counters[key]; ok {
			a.counters[key] = b
		}
	}
}
func validateRules(rs []Rule) error {
	if len(rs) > 100 {
		return errors.New("máximo de 100 regras")
	}
	ids := map[string]bool{}
	for _, r := range rs {
		if !regexp.MustCompile(`^[a-z0-9_-]{1,64}$`).MatchString(r.ID) || ids[r.ID] || r.Name == "" || len(r.Name) > 120 || len(r.Pattern) > 1024 || r.Threshold < 1 || r.Threshold > 1000 || r.Window < 1 || r.Window > 3600 || r.Level < 1 || r.Level > 15 || (r.Kind != "any" && r.Kind != "pfsense" && r.Kind != "proxmox" && r.Kind != "generic" && r.Kind != "unifi" && r.Kind != "snmp" && r.Kind != "webhook") {
			return errors.New("regra inválida")
		}
		if r.Block && (r.Kind == "snmp" || r.Kind == "unifi" || r.Kind == "webhook") {
			return errors.New("regras UniFi, SNMP e webhook somente alertam")
		}
		if _, e := regexp.Compile(r.Pattern); e != nil {
			return e
		}
		ids[r.ID] = true
	}
	return nil
}
func (a *App) device(ip string) (Device, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range a.cfg.Devices {
		if d.IP == ip {
			return d, true
		}
	}
	return Device{}, false
}
func (a *App) syslog() error {
	udp, e := net.ListenPacket("udp", a.cfg.Syslog)
	if e != nil {
		return e
	}
	tcp, e := net.Listen("tcp", a.cfg.Syslog)
	if e != nil {
		udp.Close()
		return e
	}
	go func() {
		defer udp.Close()
		b := make([]byte, 65536)
		for {
			n, addr, e := udp.ReadFrom(b)
			if e != nil {
				return
			}
			host, _, _ := net.SplitHostPort(addr.String())
			if d, ok := a.device(host); ok {
				a.ingest(d, string(b[:n]))
			}
		}
	}()
	sem := make(chan struct{}, 32)
	go func() {
		defer tcp.Close()
		for {
			conn, e := tcp.Accept()
			if e != nil {
				return
			}
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			_, ok := a.device(host)
			if !ok {
				conn.Close()
				continue
			}
			select {
			case sem <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			go func() {
				defer conn.Close()
				defer func() { <-sem }()
				s := bufio.NewScanner(conn)
				s.Buffer(make([]byte, 4096), 16384)
				conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
				for s.Scan() {
					current, allowed := a.device(host)
					if !allowed {
						return
					}
					a.ingest(current, s.Text())
					conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
				}
			}()
		}
	}()
	return nil
}
func (a *App) maintenance() {
	for range time.Tick(time.Minute) {
		a.mu.Lock()
		now := time.Now()
		if a.cfg.LocalAnalysis && a.analyzer != nil {
			devices := append([]Device(nil), a.cfg.Devices...)
			for _, source := range a.state.Receivers.Sources {
				devices = append(devices, snmpDevice(source))
			}
			a.analyzer.maintain(now, devices)
		}
		changed := false
		for k, b := range a.state.Blocks {
			if now.After(b.Expires) {
				delete(a.state.Blocks, k)
				a.audit("engine", "expiração "+k)
				changed = true
			}
		}
		if changed {
			if e := a.persist(); e != nil {
				a.storageError = e.Error()
			}
		}
		for k, s := range a.sessions {
			if now.After(s.Expires) || (!a.active[k].IsZero() && now.Sub(a.active[k]) > 15*time.Minute) {
				delete(a.sessions, k)
				delete(a.active, k)
			}
		}
		for k, b := range a.rates {
			if now.Sub(b.Start) > 10*time.Minute {
				delete(a.rates, k)
			}
		}
		for k, s := range a.oauth {
			if now.After(s.Expires) {
				delete(a.oauth, k)
			}
		}
		for k, b := range a.counters {
			if len(b.Times) == 0 || now.Sub(b.Times[len(b.Times)-1]) > time.Hour {
				delete(a.counters, k)
			}
		}
		for k, t := range a.seen {
			if now.Sub(t) > time.Hour {
				delete(a.seen, k)
			}
		}
		entries, _ := filepath.Glob(filepath.Join(a.cfg.DataDir, "events-*.jsonl"))
		for _, p := range entries {
			d, e := time.Parse("2006-01-02", strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "events-"), ".jsonl"))
			if e == nil && d.Before(now.UTC().Truncate(24*time.Hour).AddDate(0, 0, -a.cfg.RetentionDays+1)) {
				if e = os.Remove(p); e != nil {
					a.storageError = e.Error()
				}
			}
		}
		a.mu.Unlock()
	}
}
func (a *App) mailWorker() {
	for e := range a.mailQ {
		a.mu.Lock()
		to := a.cfg.MailTo
		a.mu.Unlock()
		status := "Gmail não configurado"
		if secret("GMAIL_USER") != "" && secret("GMAIL_APP_PASSWORD") != "" && to != "" && !a.demo {
			if err := sendMail(to, e); err != nil {
				status = "Falha SMTP; verifique conectividade, política da conta e credenciais"
			} else {
				status = "Enviado em " + time.Now().Format(time.RFC3339)
			}
		}
		a.mu.Lock()
		a.mailStatus = status
		a.audit("mailer", status)
		if err := a.persist(); err != nil {
			a.storageError = err.Error()
		}
		a.mu.Unlock()
	}
}
func sendMail(to string, e Event) error {
	user := secret("GMAIL_USER")
	m, err := mail.ParseAddress(user)
	if err != nil || m.Address != user {
		return errors.New("GMAIL_USER inválido")
	}
	conn, err := net.DialTimeout("tcp", "smtp.gmail.com:587", 10*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	c, err := smtp.NewClient(conn, "smtp.gmail.com")
	if err != nil {
		return err
	}
	defer c.Close()
	if err = c.StartTLS(&tls.Config{ServerName: "smtp.gmail.com", MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if err = c.Auth(smtp.PlainAuth("", user, secret("GMAIL_APP_PASSWORD"), "smtp.gmail.com")); err != nil {
		return err
	}
	if err = c.Mail(user); err != nil {
		return err
	}
	if err = c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	body := fmt.Sprintf("Multipla Siem\nAlerta: %s\nDispositivo: %s\nIP: %s\nNível: %d\nHorário: %s\n\nEntre no painel autorizado para investigar os detalhes.", redact(e.Rule), redact(e.Device), e.SourceIP, e.Level, e.Time.Format(time.RFC3339))
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	var lines strings.Builder
	for len(encoded) > 76 {
		lines.WriteString(encoded[:76] + "\r\n")
		encoded = encoded[76:]
	}
	lines.WriteString(encoded + "\r\n")
	msg := "From: " + user + "\r\nTo: " + to + "\r\nSubject: [Multipla Siem] Alerta de seguranca\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n" + lines.String()
	if _, err = io.WriteString(w, msg); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !jsonContent(w, r) {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		http.Error(w, "JSON inválido: "+e.Error(), 400)
		return false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		http.Error(w, "apenas um documento JSON", 400)
		return false
	}
	return true
}
func (a *App) session(r *http.Request) (Session, bool) {
	value, valid := a.cookieValue(r, a.sessionName())
	if !valid {
		return Session{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	s, ok := a.sessions[value]
	if !ok || !time.Now().Before(s.Expires) || a.roleLocked(s.Email) == "disabled" {
		return Session{}, false
	}
	if last := a.active[value]; !last.IsZero() && time.Since(last) > 15*time.Minute {
		delete(a.sessions, value)
		delete(a.active, value)
		return Session{}, false
	}
	if s.Email != "bootstrap" && !(a.demo && s.Email == "demo@multipla-siem.local") {
		allowed := false
		for _, email := range a.cfg.AllowedEmails {
			if strings.EqualFold(email, s.Email) {
				allowed = true
			}
		}
		if !allowed {
			delete(a.sessions, value)
			delete(a.active, value)
			return Session{}, false
		}
	}
	return s, true
}
func (a *App) secure() bool { return strings.HasPrefix(a.origin, "https://") }
func (a *App) cookie(w http.ResponseWriter, name, value string, age int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.secure(), SameSite: http.SameSiteLaxMode, MaxAge: age})
}
func (a *App) newSession(w http.ResponseWriter, r *http.Request, email string, subjects ...string) {
	subject := ""
	if len(subjects) > 0 {
		subject = subjects[0]
	}
	t := token()
	a.mu.Lock()
	if len(a.sessions) >= 1000 {
		a.mu.Unlock()
		http.Error(w, "limite de sessões", 503)
		return
	}
	if old, ok := a.cookieValue(r, a.sessionName()); ok {
		delete(a.sessions, old)
		delete(a.active, old)
	}
	if subject != "" {
		if _, exists := a.state.GoogleSubjects[strings.ToLower(email)]; !exists && len(a.state.GoogleSubjects) >= 102 {
			a.mu.Unlock()
			http.Error(w, "limite de contas Google", 503)
			return
		}
		for id, existing := range a.sessions {
			if strings.EqualFold(existing.Email, email) && existing.Subject != subject {
				delete(a.sessions, id)
				delete(a.active, id)
			}
		}
		a.state.GoogleSubjects[strings.ToLower(email)] = subject
	}
	a.sessions[t] = Session{Subject: subject, Email: email, CSRF: token(), Expires: time.Now().Add(8 * time.Hour)}
	a.active[t] = time.Now()
	a.audit(email, "autenticação bem-sucedida")
	if e := a.persist(); e != nil {
		delete(a.sessions, t)
		delete(a.active, t)
		a.mu.Unlock()
		http.Error(w, "falha na auditoria; acesso não iniciado", 503)
		return
	}
	a.mu.Unlock()
	a.cookie(w, a.sessionName(), t, 0)
	http.Redirect(w, r, "/", 303)
}
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.session(r)
		if !ok {
			http.Error(w, "Entre para continuar", 401)
			return
		}
		a.mu.Lock()
		role := a.roleLocked(s.Email)

		a.mu.Unlock()
		if role != "admin" && r.URL.Path != "/auth/logout" && r.URL.Path != "/api/activity" && !(r.Method == "PUT" && r.URL.Path == "/api/dashboard/layout") && !(r.Method == "POST" && r.URL.Path == "/api/notifications/clear") && !(r.Method == "POST" && (r.URL.Path == "/api/assistant/plan" || r.URL.Path == "/api/assistant/query")) && (r.Method != "GET" || (r.URL.Path != "/api/snapshot" && r.URL.Path != "/api/export" && r.URL.Path != "/api/events/history" && r.URL.Path != "/api/devices/metrics" && r.URL.Path != "/api/devices/resource-history" && r.URL.Path != "/api/system/health" && r.URL.Path != "/api/system/usage-history" && r.URL.Path != "/api/notifications" && r.URL.Path != "/api/events/critical-ips" && r.URL.Path != "/api/dashboard/distribution" && r.URL.Path != "/api/dashboard/activity" && r.URL.Path != "/api/reports" && r.URL.Path != "/api/network")) {
			http.Error(w, "Perfil somente visualizacao: operacao nao permitida", 403)
			return
		}
		if r.Method != "GET" {
			if r.Header.Get("Origin") != a.origin || !equal(r.Header.Get("X-CSRF-Token"), s.CSRF) {
				http.Error(w, "CSRF inválido", 403)
				return
			}
		}
		next(w, r)
	}
}
func (a *App) oauthStart(w http.ResponseWriter, r *http.Request) {
	if a.demo {
		http.Error(w, "Google desativado na demonstração", 503)
		return
	}
	if a.googleSecret("GOOGLE_CLIENT_ID") == "" || a.googleSecret("GOOGLE_CLIENT_SECRET") == "" {
		http.Error(w, "Configure GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET", 503)
		return
	}
	state, verifier := token(), token()
	a.mu.Lock()
	if len(a.oauth) >= 1000 {
		a.mu.Unlock()
		http.Error(w, "limite de autenticações", 429)
		return
	}
	a.oauth[state] = OAuth{Verifier: verifier, Expires: time.Now().Add(5 * time.Minute)}
	a.mu.Unlock()
	a.cookie(w, a.oauthName(), state, 300)
	hash := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {a.googleSecret("GOOGLE_CLIENT_ID")}, "redirect_uri": {a.origin + "/auth/callback"}, "response_type": {"code"}, "scope": {"openid email"}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(hash[:])}, "code_challenge_method": {"S256"}}
	http.Redirect(w, r, "https://accounts.google.com/o/oauth2/v2/auth?"+q.Encode(), 302)
}
func (a *App) oauthCallback(w http.ResponseWriter, r *http.Request) {
	state := r.URL.Query().Get("state")
	value, valid := a.cookieValue(r, a.oauthName())
	if !valid || !equal(value, state) {
		http.Error(w, "Estado OAuth inválido", 403)
		return
	}
	a.mu.Lock()
	flow, ok := a.oauth[state]
	delete(a.oauth, state)
	a.mu.Unlock()
	a.cookie(w, a.oauthName(), "", -1)
	if !ok || time.Now().After(flow.Expires) {
		http.Error(w, "Login expirado", 403)
		return
	}
	resp, e := client.PostForm("https://oauth2.googleapis.com/token", url.Values{"code": {r.URL.Query().Get("code")}, "client_id": {a.googleSecret("GOOGLE_CLIENT_ID")}, "client_secret": {a.googleSecret("GOOGLE_CLIENT_SECRET")}, "redirect_uri": {a.origin + "/auth/callback"}, "grant_type": {"authorization_code"}, "code_verifier": {flow.Verifier}})
	if e != nil {
		http.Error(w, "Google indisponível", 502)
		return
	}
	defer resp.Body.Close()
	var t struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&t) != nil || t.AccessToken == "" {
		http.Error(w, "Falha na autenticação", 403)
		return
	}
	req, _ := http.NewRequest("GET", "https://openidconnect.googleapis.com/v1/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+t.AccessToken)
	ur, e := client.Do(req)
	if e != nil {
		http.Error(w, "Google indisponível", 502)
		return
	}
	defer ur.Body.Close()
	var u struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
		Sub      string `json:"sub"`
	}
	if ur.StatusCode != 200 || json.NewDecoder(io.LimitReader(ur.Body, 65536)).Decode(&u) != nil || !u.Verified || u.Sub == "" {
		http.Error(w, "Email não verificado", 403)
		return
	}
	a.mu.Lock()
	allowed := false
	for _, em := range a.cfg.AllowedEmails {
		if strings.EqualFold(em, u.Email) {
			allowed = true
		}
	}
	a.mu.Unlock()
	if !allowed {
		http.Error(w, "Conta sem autorização", 403)
		return
	}
	if flow.DriveEmail != "" {
		s, valid := a.session(r)
		granted := false
		for _, scope := range strings.Fields(t.Scope) {
			if scope == driveScope {
				granted = true
			}
		}
		if !valid || !strings.EqualFold(s.Email, flow.DriveEmail) || !strings.EqualFold(u.Email, flow.DriveEmail) || u.Sub != flow.DriveSubject || s.Subject != flow.DriveSubject || !granted || t.RefreshToken == "" || len(t.RefreshToken) > 4096 || len(t.AccessToken) > 4096 || t.ExpiresIn <= 0 || t.ExpiresIn > 86400 {
			http.Error(w, "Conta ou permissão Drive inválida; conecte a mesma conta do login", 403)
			return
		}
		if e := a.storeDriveToken(s.Email, DriveToken{Subject: u.Sub, Access: t.AccessToken, Refresh: t.RefreshToken, Expires: time.Now().Add(time.Duration(t.ExpiresIn) * time.Second), Scope: t.Scope}); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		http.Redirect(w, r, "/", 303)
		return
	}
	a.newSession(w, r, u.Email, u.Sub)
}
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	a.registerAccountRoutes(mux)
	a.registerAlertRoutes(mux)
	a.registerCriticalPatternRoutes(mux)
	a.registerLocalAIRoutes(mux)
	a.registerAssistantRoutes(mux)
	a.registerHostHistoryRoute(mux)
	a.registerHistoryRoutes(mux)
	a.registerBackupRoutes(mux)
	a.registerDashboardRoutes(mux)
	a.registerReportRoutes(mux)
	a.registerNetworkRoutes(mux)
	a.registerDeviceNetworkRoutes(mux)
	a.registerDeviceMetricRoutes(mux)
	a.registerResourceHistoryRoutes(mux)
	a.registerHostHealthRoutes(mux)
	a.registerSystemRoutes(mux)
	a.registerSSHRoutes(mux)
	a.registerDHCPRoutes(mux)
	a.registerTemporaryReportRoutes(mux)
	a.registerLocalAuth(mux)
	a.registerGoogleSettings(mux)
	a.registerReceiverRoutes(mux)
	a.registerN8NRoutes(mux)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		page := "web/login.html"
		if _, ok := a.session(r); ok {
			page = "web/index.html"
		}
		b, _ := assets.ReadFile(page)
		// Only trusted terminal style elements receive this per-response nonce.
		nonce := token()
		policy := w.Header().Get("Content-Security-Policy")
		w.Header().Set("Content-Security-Policy", strings.Replace(policy, "style-src 'self'", "style-src 'self' 'nonce-"+nonce+"'", 1))
		b = []byte(strings.Replace(string(b), "<head>", "<head><meta name=\"terminal-style-nonce\" content=\""+nonce+"\">", 1))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
	for _, path := range []string{"assistant.js", "host-chart.js", "style.css", "favicon.svg", "alert-sounds.js", "critical-controls.js", "host-health.js", "device-network.js", "app.js", "backup.js", "accounts.js", "login.js", "receivers.js", "n8n.js", "dashboard.js", "reports.js", "network.js", "ssh.js", "dhcp.js", "test-reports.js", "xterm.js", "xterm.css"} {
		p := path
		mux.HandleFunc("GET /"+p, func(w http.ResponseWriter, r *http.Request) {
			if p == "assistant.js" || p == "host-chart.js" || p == "host-health.js" || p == "critical-controls.js" || p == "n8n.js" || p == "alert-sounds.js" || p == "device-network.js" || p == "app.js" || p == "backup.js" || p == "accounts.js" || p == "login.js" || p == "receivers.js" || p == "dashboard.js" || p == "reports.js" || p == "network.js" || p == "ssh.js" || p == "dhcp.js" || p == "test-reports.js" || p == "xterm.js" {
				w.Header().Set("Content-Type", "text/javascript")
			} else if p == "favicon.svg" {
				w.Header().Set("Content-Type", "image/svg+xml")
			} else {
				w.Header().Set("Content-Type", "text/css")
			}
			b, _ := assets.ReadFile("web/" + p)
			w.Write(b)
		})
	}
	registerAlertSoundAssets(mux)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /auth/google", a.oauthStart)
	mux.HandleFunc("GET /auth/callback", a.oauthCallback)
	mux.HandleFunc("POST /auth/local", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2048)
		if r.ParseForm() != nil {
			http.Error(w, "formulário inválido", 400)
			return
		}
		if r.Header.Get("Origin") != a.origin {
			http.Error(w, "origem inválida", 403)
			return
		}
		if a.demo {
			a.newSession(w, r, "demo@multipla-siem.local")
			return
		}
		if !equal(secret("BOOTSTRAP_TOKEN"), r.FormValue("token")) {
			a.securityEvent("tentativa de acesso inicial rejeitada", a.clientIP(r))
			http.Error(w, "Token inválido", 403)
			return
		}
		a.mu.Lock()
		digestBytes := sha256.Sum256([]byte(secret("BOOTSTRAP_TOKEN")))
		digest := base64.RawURLEncoding.EncodeToString(digestBytes[:])
		ttl := 15 * time.Minute
		if a.cfg.FirstBoot && a.state.LocalAdmin.Hash == "" {
			ttl = 24 * time.Hour
		}
		unavailable := a.bootstrapUsed || a.state.BootstrapDigest == digest || time.Since(a.bootAt) > ttl
		if !unavailable {
			old := a.state.BootstrapDigest
			a.state.BootstrapDigest = digest
			if e := a.persist(); e != nil {
				a.state.BootstrapDigest = old
				a.mu.Unlock()
				http.Error(w, "falha ao registrar acesso inicial", 503)
				return
			}
			a.bootstrapUsed = true
		}
		a.mu.Unlock()
		if unavailable {
			http.Error(w, "Acesso inicial expirado ou já utilizado; use Google", 403)
			return
		}
		a.newSession(w, r, "bootstrap")
	})
	mux.HandleFunc("POST /auth/logout", a.auth(func(w http.ResponseWriter, r *http.Request) {
		value, _ := a.cookieValue(r, a.sessionName())
		a.mu.Lock()
		owner := a.sessions[value].Email
		delete(a.sessions, value)
		delete(a.active, value)
		for _, terminal := range a.sshTerminals {
			if strings.EqualFold(terminal.owner, owner) {
				terminal.close("Sessão SIEM encerrada")
			}
		}
		a.mu.Unlock()
		a.securityEvent("sessão encerrada", a.clientIP(r))
		a.cookie(w, a.sessionName(), "", -1)
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/activity", a.auth(func(w http.ResponseWriter, r *http.Request) {
		value, _ := a.cookieValue(r, a.sessionName())
		a.mu.Lock()
		a.active[value] = time.Now()
		a.mu.Unlock()
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/snapshot", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		q := strings.ToLower(r.URL.Query().Get("q"))
		var evs []Event
		alerts := 0
		bins := make([]int, 30)
		for i := len(a.events) - 1; i >= 0; i-- {
			e := a.events[i]
			if review, ok := a.state.AlertReviews[e.ID]; ok {
				copy := review
				e.Review = &copy
				if copy.Level >= 12 && copy.Status != "false_positive" {
					marked := e
					marked.Level = copy.Level
					e.Diagnosis = localDiagnosis(marked)
				}
			}
			if result, ok := a.state.ModelDiagnoses[diagnosisKey(e)]; ok {
				copy := result
				e.ModelDiagnosis = &copy
			}
			if e.Diagnosis == nil {
				e.Diagnosis = localDiagnosis(e)
			}
			e = a.classifiedEvent(e)
			minute := int(time.Since(e.Time) / time.Minute)
			if (!e.Alert || e.Kind == "wazuh") && minute >= 0 && minute < 30 {
				bins[29-minute]++
			}
			if e.Alert {
				alerts++
			}
			if len(evs) < 250 && (q == "" || strings.Contains(strings.ToLower(e.Message+e.Device+e.SourceIP+e.Rule), q)) {
				evs = append(evs, e)
			}
		}
		var blocks []Block
		for _, b := range a.state.Blocks {
			if time.Now().Before(b.Expires) {
				blocks = append(blocks, b)
			}
		}
		sort.Slice(blocks, func(i, j int) bool { return blocks[i].IP < blocks[j].IP })
		total := a.total
		if a.totalDay != time.Now().UTC().Format("2006-01-02") {
			total = 0
		}
		snmpDevices := []Device{}
		for _, source := range a.state.Receivers.Sources {
			snmpDevices = append(snmpDevices, snmpDevice(source))
		}
		role := a.roleLocked(s.Email)
		visiblePresence := map[string]bool{}
		for _, device := range append(append([]Device{}, a.cfg.Devices...), snmpDevices...) {
			if online, ok := a.devicePresence[device.IP]; ok {
				visiblePresence[device.IP] = online
			}
		}
		visibleConfig := a.cfg
		visibleAudit := a.state.Audit
		if role != "admin" {
			visibleConfig.AllowedEmails = []string{s.Email}
			visibleConfig.FeedAllowed = nil
			visibleConfig.MailTo = ""
			visibleAudit = nil
		}
		memoryIDs := map[string]bool{}
		for _, e := range a.events {
			memoryIDs[e.ID] = true
		}
		cutoff := time.Now().AddDate(0, 0, -a.cfg.RetentionDays)
		for _, policy := range a.state.CriticalPatterns {
			if !memoryIDs[policy.Seed.ID] && !policy.Seed.Time.Before(cutoff) {
				e := a.classifiedEvent(policy.Seed)
				if e.Level >= 12 && (e.Review == nil || e.Review.Status != "false_positive") {
					alerts++
				}
			}
		}
		writeJSON(w, map[string]any{"role": role, "snmp_devices": snmpDevices, "event_clients": a.eventClientIndex(), "preferences": a.preferences(s.Email), "drive_connected": a.state.DriveTokens[strings.ToLower(s.Email)] != "", "analysis": a.analysisSnapshot(), "local_ai": a.localAISnapshot(), "events": evs, "critical_events": a.criticalDashboardEvents(), "alerts": alerts, "total": total, "bins": bins, "blocks": blocks, "config": visibleConfig, "rules": a.state.Rules, "audit": visibleAudit, "last_seen": a.lastSeen, "device_presence": visiblePresence, "mail_status": a.mailStatus, "storage_error": a.storageError, "dropped": a.dropped, "feed_seen": a.feedSeen, "email": s.Email, "csrf": s.CSRF, "demo": a.demo, "local_account_ready": a.state.LocalAdmin.Hash != "", "google_ready": a.state.GoogleSettings != "" || secret("GOOGLE_CLIENT_ID") != "", "mail_ready": secret("GMAIL_APP_PASSWORD") != ""})
	}))
	mux.HandleFunc("PUT /api/config", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var c Config
		if !decode(w, r, &c) {
			return
		}
		if e := validateConfig(c); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		c.Listen = a.cfg.Listen
		c.Syslog = a.cfg.Syslog
		c.SNMP = a.cfg.SNMP
		c.DataDir = a.cfg.DataDir
		c.PublicURL = a.cfg.PublicURL
		c.TLSCert = a.cfg.TLSCert
		c.TLSKey = a.cfg.TLSKey
		c.LocalAnalysis = true
		if a.demo && c.AutoBlock {
			http.Error(w, "Demo permite apenas simulação", 400)
			return
		}
		if e := atomicJSON(a.configPath, c); e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		if c.LocalAnalysis != a.cfg.LocalAnalysis {
			a.analyzer = nil
		}
		for _, previous := range a.cfg.Devices {
			keep := false
			for _, next := range c.Devices {
				if next.IP == previous.IP && next.Name == previous.Name {
					keep = true
				}
			}
			if !keep {
				delete(a.state.MetricKeys, previous.IP)
				delete(a.state.DeviceMetrics, previous.IP)
			}
		}
		a.cfg = c
		a.audit(s.Email, "configuração atualizada")
		if e := a.persist(); e != nil {
			http.Error(w, "Configuração salva, auditoria falhou: "+e.Error(), 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/rules/test", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Pattern string `json:"pattern"`
			Kind    string `json:"kind"`
			Message string `json:"message"`
		}
		if !decode(w, r, &input) {
			return
		}
		if len(input.Pattern) == 0 || len(input.Pattern) > 1024 || len(input.Message) > 16384 {
			http.Error(w, "Padrão ou mensagem excede o limite", 400)
			return
		}
		re, err := regexp.Compile(input.Pattern)
		if err != nil {
			http.Error(w, "Padrão Go/RE2 inválido: "+err.Error(), 400)
			return
		}
		checked, matches := 0, 0
		a.mu.Lock()
		for _, event := range a.events {
			if input.Kind != "any" && input.Kind != event.Kind {
				continue
			}
			checked++
			if re.MatchString(event.Message) {
				matches++
			}
		}
		a.mu.Unlock()
		writeJSON(w, map[string]any{"sample_match": re.MatchString(input.Message), "checked": checked, "matches": matches})
	}))
	mux.HandleFunc("PUT /api/rules", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var rs []Rule
		if !decode(w, r, &rs) {
			return
		}
		if e := validateRules(rs); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		old := a.state.Rules
		oldAudit := append([]Audit(nil), a.state.Audit...)
		a.state.Rules = rs
		a.audit(s.Email, "regras atualizadas")
		if e := a.persist(); e != nil {
			a.state.Rules = old
			a.state.Audit = oldAudit
			http.Error(w, e.Error(), 500)
			return
		}
		a.counters = map[string]bucket{}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/blocks", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if !decode(w, r, &b) {
			return
		}
		if len(b.Reason) > 256 {
			http.Error(w, "motivo muito longo", 400)
			return
		}
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		if e := a.block(b.IP, b.Reason, s.Email); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("PUT /api/blocks/{ip}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Reason string `json:"reason"`
		}
		if !decode(w, r, &input) {
			return
		}
		input.Reason = strings.TrimSpace(input.Reason)
		if input.Reason == "" || len(input.Reason) > 256 {
			http.Error(w, "Informe motivo de até 256 caracteres", 400)
			return
		}
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		ip := r.PathValue("ip")
		old, ok := a.state.Blocks[ip]
		if !ok || !old.Expires.After(time.Now()) {
			http.Error(w, "Resposta não encontrada ou expirada", 404)
			return
		}
		changed := old
		changed.Reason = input.Reason
		oldAudit := append([]Audit(nil), a.state.Audit...)
		a.state.Blocks[ip] = changed
		a.audit(session.Email, "edição do motivo da resposta "+ip)
		if err := a.persist(); err != nil {
			a.state.Blocks[ip] = old
			a.state.Audit = oldAudit
			http.Error(w, "Falha ao salvar a resposta", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("DELETE /api/blocks/{ip}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		ip := r.PathValue("ip")
		b, had := a.state.Blocks[ip]
		oldAudit := append([]Audit(nil), a.state.Audit...)
		delete(a.state.Blocks, ip)
		a.audit(s.Email, "remoção "+ip)
		if e := a.persist(); e != nil {
			if had {
				a.state.Blocks[ip] = b
			}
			a.state.Audit = oldAudit
			http.Error(w, e.Error(), 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/export", a.auth(func(w http.ResponseWriter, r *http.Request) {
		day := r.URL.Query().Get("day")
		d, e := time.Parse("2006-01-02", day)
		if e != nil {
			http.Error(w, "data inválida", 400)
			return
		}
		a.mu.Lock()
		p := a.journalPath(d)
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="events-`+day+`.jsonl"`)
		if e := regularFile(p); e != nil {
			http.NotFound(w, r)
			return
		}
		streamEventExport(w, r, p)
	}))
	mux.HandleFunc("POST /api/mail/test", a.auth(func(w http.ResponseWriter, r *http.Request) {
		select {
		case a.mailQ <- Event{Time: time.Now(), Rule: "Teste de notificação", Message: "Integração Gmail configurada.", Level: 10}:
			writeJSON(w, map[string]bool{"queued": true})
		default:
			http.Error(w, "fila cheia", 429)
		}
	}))
	mux.HandleFunc("GET /feeds/pfsense/{token}", func(w http.ResponseWriter, r *http.Request) {
		if a.demo || !equal(secret("PFSENSE_FEED_TOKEN"), r.PathValue("token")) {
			http.Error(w, "não autorizado", 401)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if !a.feedAllowed(r) {
			http.Error(w, "origem não autorizada para feed", 403)
			return
		}
		a.feedSeen = time.Now().UTC()
		w.Header().Set("Content-Type", "text/plain")
		var ips []string
		for _, b := range a.state.Blocks {
			ip, e := netip.ParseAddr(b.IP)
			if e == nil && a.cfg.AutoBlock && b.Mode == "published" && time.Now().Before(b.Expires) && !a.protected(ip) {
				ips = append(ips, b.IP)
			}
		}
		sort.Strings(ips)
		if len(ips) == 0 {
			io.WriteString(w, "# Multipla Siem: lista vazia\n")
		} else {
			io.WriteString(w, strings.Join(ips, "\n")+"\n")
		}
	})
	mux.HandleFunc("POST /api/wazuh", a.wazuh)
	mux.HandleFunc("POST /api/demo", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if !a.demo {
			http.NotFound(w, r)
			return
		}
		for i := 0; i < 6; i++ {
			a.ingest(Device{Name: "Proxmox demo", IP: "192.168.1.10", Kind: "proxmox"}, "sshd: Failed password for root from 198.51.100.42 port 4456 ssh2")
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(self), geolocation=(), payment=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		if a.secure() {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if !a.requestGuard(w, r) {
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) wazuh(w http.ResponseWriter, r *http.Request) {
	if a.demo || len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || !equal(secret("INGEST_TOKEN"), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) {
		http.Error(w, "não autorizado", 401)
		return
	}
	if !jsonContent(w, r) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	var v struct {
		ID   string `json:"id"`
		Rule struct {
			ID          string `json:"id"`
			Level       int    `json:"level"`
			Description string `json:"description"`
		} `json:"rule"`
		Agent struct {
			Name string `json:"name"`
		} `json:"agent"`
		Data struct {
			SrcIP string `json:"srcip"`
		} `json:"data"`
		FullLog string `json:"full_log"`
	}
	decoder := json.NewDecoder(r.Body)
	if decoder.Decode(&v) != nil || v.ID == "" || len(v.ID) > 256 || len(v.Rule.ID) > 256 || v.Rule.Level < 1 || v.Rule.Level > 15 || len(v.FullLog) > 16384 || len(v.Rule.Description) > 512 || len(v.Agent.Name) > 128 {
		http.Error(w, "alerta Wazuh inválido", 400)
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		http.Error(w, "apenas um alerta JSON por requisição", 400)
		return
	}
	ip := ""
	if p, e := netip.ParseAddr(v.Data.SrcIP); e == nil {
		ip = p.Unmap().String()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.seen[v.ID]; ok {
		writeJSON(w, map[string]bool{"duplicate": true})
		return
	}
	if len(a.seen) >= 10000 {
		http.Error(w, "limite de deduplicação; tente novamente", 429)
		return
	}
	ev := Event{ID: token(), Time: time.Now().UTC(), Device: redact(v.Agent.Name), Kind: "wazuh", SourceIP: ip, Message: redact(v.FullLog), Level: v.Rule.Level, Rule: redact("Wazuh " + v.Rule.ID + ": " + v.Rule.Description), Alert: true}
	if !a.appendEvent(ev) {
		http.Error(w, "falha de armazenamento", 503)
		return
	}
	a.seen[v.ID] = time.Now()
	if ev.Level >= a.cfg.MailMinLevel {
		select {
		case a.mailQ <- ev:
		default:
			a.mailStatus = "Fila cheia"
		}
	}
	writeJSON(w, map[string]bool{"ok": true})
}
func main() {
	path := flag.String("config", "config.json", "arquivo de configuração")
	demo := flag.Bool("demo", false, "demonstração local sem integrações externas")
	firstBoot := flag.Bool("firstboot", false, "configuração automática HTTPS no primeiro boot")
	setup := flag.Bool("setup", false, "configuração guiada da instalação Linux")
	version := flag.Bool("version", false, "mostrar versão")
	check := flag.Bool("check", false, "validar configuração e credenciais sem iniciar o servidor")
	fullBackup := flag.Bool("full-backup", false, "backup completo criptografado como root")
	fullRestore := flag.String("full-restore", "", "arquivo de recuperacao completo")
	recoveryFile := flag.String("recovery-key", "", "arquivo privado com a chave de recuperacao")
	backupDrive := flag.String("backup-drive", "", "email Google ja autorizado para receber backup completo")
	replaceServer := flag.Bool("replace-server", false, "confirmar que o servidor original esta desligado")
	fullSchedule := flag.String("full-backup-schedule", "", "agendar backup completo diario para uma conta Drive")
	fullLocked := flag.Bool("full-locked", false, "trava interna do backup completo")
	enableReboot := flag.Bool("enable-server-reboot", false, "instalar política restrita de reinício como root")
	flag.Parse()
	if *enableReboot {
		if err := enableServerReboot(); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Política restrita de reinício instalada.")
		return
	}
	if *fullBackup || *fullRestore != "" || *fullSchedule != "" {
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			log.Fatal("backup completo exige root no Debian/Ubuntu")
		}
		if !*fullLocked {
			executable, err := os.Executable()
			if err != nil {
				log.Fatal(err)
			}
			args := append([]string{"-n", "/run/multipla-update.lock", "flock", "-n", "/run/multipla-updater-operation.lock", executable, "-full-locked"}, os.Args[1:]...)
			cmd := exec.Command("flock", args...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			if err := cmd.Run(); err != nil {
				os.Exit(1)
			}
			return
		}
		if *fullSchedule != "" {
			if err := installFullBackupSchedule(*fullSchedule); err != nil {
				log.Fatal(err)
			}
			return
		}
		if err := runFullBackup(*fullRestore, *backupDrive, *recoveryFile, *replaceServer); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *version {
		fmt.Println("Multipla Siem " + productVersion())
		return
	}
	if *firstBoot {
		if err := automaticFirstBoot(); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *setup {
		if e := runSetup(); e != nil {
			log.Fatal(e)
		}
		return
	}
	if e := loadCredentials(); e != nil {
		log.Fatal(e)
	}
	var c Config
	b, e := os.ReadFile(*path)
	if e != nil {
		log.Fatal(e)
	}
	if e = json.Unmarshal(b, &c); e != nil {
		log.Fatal(e)
	}
	if *demo {
		c.Listen = "127.0.0.1:8787"
		c.Syslog = "127.0.0.1:5514"
		c.PublicURL = "http://127.0.0.1:8787"
		c.AutoBlock = false
		c.TLSCert = ""
		c.TLSKey = ""
	}
	if !*demo {
		if e := validateProduction(c); e != nil {
			log.Fatal(e)
		}
	}
	if e := validateConfig(c); e != nil {
		log.Fatal(e)
	}
	if *check {
		if c.TLSCert != "" {
			if _, e := tls.LoadX509KeyPair(c.TLSCert, c.TLSKey); e != nil {
				log.Fatal("par TLS inválido")
			}
		}
		fmt.Println("Multipla Siem: configuração verificada")
		return
	}
	a, e := newApp(c, *path, *demo)
	if e != nil {
		log.Fatal(e)
	}
	if e = a.syslog(); e != nil {
		log.Fatal(e)
	}
	go a.maintenance()
	go a.localAIWorker()
	go a.devicePresenceWorker()
	go a.resourceHistoryWorker()
	go a.hostHealthWorker()
	go a.backupScheduler()
	go a.temporaryReportCleaner()
	go a.mailWorker()
	go a.webhookWorker()
	go a.n8nWorker()
	go a.snmpWorker()
	srv := &http.Server{Addr: c.Listen, Handler: a.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	log.Printf("Multipla Siem em %s; syslog TCP/UDP %s; demo=%t", c.Listen, c.Syslog, *demo)
	if a.nativeTLS {
		srv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		log.Fatal(srv.ListenAndServeTLS(c.TLSCert, c.TLSKey))
	}
	log.Fatal(srv.ListenAndServe())
}
