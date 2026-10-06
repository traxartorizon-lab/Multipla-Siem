package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	_ "time/tzdata"
)

const backupLimit = 1024 * 1024

type Preferences struct {
	DashboardOrder []string `json:"dashboard_order,omitempty"`
	DefaultPage    string   `json:"default_page"`
	RefreshSeconds int      `json:"refresh_seconds"`
	AlertMinLevel  int      `json:"alert_min_level"`
	BackupDaily    bool     `json:"backup_daily"`
	BackupTime     string   `json:"backup_time"`
	BackupTimezone string   `json:"backup_timezone"`
	BackupDrive    bool     `json:"backup_drive"`
}

func defaultPreferences() Preferences {
	return Preferences{DefaultPage: "overview", RefreshSeconds: 5, AlertMinLevel: 1, BackupTime: "02:00", BackupTimezone: "America/Sao_Paulo"}
}
func validatePreferences(p Preferences) error {
	if err := validateDashboardOrder(p.DashboardOrder); err != nil {
		return err
	}
	switch p.DefaultPage {
	case "overview", "events", "devices", "rules", "blocks", "settings", "audit", "backups":
	default:
		return errors.New("página inicial inválida")
	}
	if p.RefreshSeconds < 2 || p.RefreshSeconds > 60 || p.AlertMinLevel < 1 || p.AlertMinLevel > 15 {
		return errors.New("preferências fora dos limites")
	}
	if _, e := time.Parse("15:04", p.BackupTime); e != nil {
		return errors.New("horário inválido; use HH:MM")
	}
	if len(p.BackupTimezone) > 80 {
		return errors.New("fuso inválido")
	}
	if _, e := time.LoadLocation(p.BackupTimezone); e != nil {
		return errors.New("fuso inválido")
	}
	return nil
}
func (a *App) preferences(email string) Preferences {
	if p, ok := a.state.Preferences[strings.ToLower(email)]; ok {
		return p
	}
	return defaultPreferences()
}

// Operational host/TLS paths and secrets are deliberately absent from the schema.
type BackupConfig struct {
	RetentionDays int      `json:"retention_days"`
	AllowedEmails []string `json:"allowed_emails"`
	Devices       []Device `json:"devices"`
	Protected     []string `json:"protected_cidrs"`
	BlockMinutes  int      `json:"block_minutes"`
	MailTo        string   `json:"mail_to"`
	MailMinLevel  int      `json:"mail_min_level"`
	FeedAllowed   []string `json:"feed_allowed_cidrs"`
	MaxDailyMB    int      `json:"max_daily_mb"`
	LocalAnalysis bool     `json:"local_analysis"`
}
type BackupDocument struct {
	NetworkEquipment *[]NetworkEquipment `json:"network_equipment,omitempty"`
	Receivers        *ReceiverSettings   `json:"receivers,omitempty"`
	Product          string              `json:"product"`
	Schema           int                 `json:"schema"`
	Version          string              `json:"version"`
	Created          time.Time           `json:"created"`
	Owner            string              `json:"owner_email"`
	Config           BackupConfig        `json:"config"`
	Rules            []Rule              `json:"rules"`
	Preferences      Preferences         `json:"preferences"`
}
type BackupEntry struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Size    int64     `json:"size"`
}

var backupName = regexp.MustCompile(`^[a-f0-9]{24}-[0-9]{20}-[a-f0-9]{16}\.json$`)

func accountPrefix(email string) string {
	h := sha256.Sum256([]byte(strings.ToLower(email)))
	return hex.EncodeToString(h[:12]) + "-"
}
func (a *App) backupDocument(email string) BackupDocument {
	c := a.cfg
	receivers := a.state.Receivers
	receivers.Sources = append([]SNMPSource{}, receivers.Sources...)
	for i := range receivers.Sources {
		receivers.Sources[i].Credentials = ""
	}
	receivers.InboundCredentials = ""
	receivers.OutboundCredentials = ""
	receivers.OutboundURL = ""
	receivers.InboundEnabled = false
	receivers.OutboundEnabled = false
	receivers.SNMPEnabled = false
	equipment := append([]NetworkEquipment{}, a.state.NetworkEquipment...)
	return BackupDocument{NetworkEquipment: &equipment, Receivers: &receivers, Product: "Multipla Siem", Schema: 1, Version: "1.2.8", Created: time.Now().UTC(), Owner: email, Config: BackupConfig{c.RetentionDays, c.AllowedEmails, c.Devices, c.Protected, c.BlockMinutes, c.MailTo, c.MailMinLevel, c.FeedAllowed, c.MaxDailyMB, c.LocalAnalysis}, Rules: a.state.Rules, Preferences: a.preferences(email)}
}
func decodeBackup(data []byte) (BackupDocument, error) {
	var b BackupDocument
	if len(data) > backupLimit {
		return b, errors.New("backup excede 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(&b); e != nil {
		return b, errors.New("backup JSON inválido ou campos não permitidos")
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return b, errors.New("backup contém dados adicionais")
	}
	if b.Product != "Multipla Siem" || b.Schema != 1 || len(b.Owner) > 254 || b.Created.IsZero() {
		return b, errors.New("formato de backup não suportado")
	}
	if e := validatePreferences(b.Preferences); e != nil {
		return b, e
	}
	if b.NetworkEquipment != nil {
		if len(*b.NetworkEquipment) > 500 {
			return b, errors.New("muitos equipamentos")
		}
		ids := map[string]bool{}
		for _, d := range *b.NetworkEquipment {
			if d.ID == "" || len(d.ID) > 128 || ids[d.ID] {
				return b, errors.New("identificador de equipamento inválido")
			}
			ids[d.ID] = true
			if err := validateEquipment(d); err != nil {
				return b, err
			}
		}
	}
	if e := validateRules(b.Rules); e != nil {
		return b, e
	}
	if b.Receivers != nil {
		receivers := *b.Receivers
		if receivers.InboundCredentials != "" || receivers.OutboundCredentials != "" || receivers.OutboundURL != "" {
			return b, errors.New("backup não pode incluir credenciais ou URL de webhook")
		}
		for _, source := range receivers.Sources {
			if source.Credentials != "" {
				return b, errors.New("backup não pode incluir credenciais SNMP")
			}
		}
		receivers.SNMPEnabled = false
		receivers.InboundEnabled = false
		receivers.OutboundEnabled = false
		if e := validateReceivers(receivers); e != nil {
			return b, e
		}
		b.Receivers = &receivers
	}
	return b, nil
}
func (a *App) restoreBackup(email string, data []byte) error {
	b, e := decodeBackup(data)
	if e != nil {
		return e
	}
	b.Preferences.BackupDaily = false
	b.Preferences.BackupDrive = false
	a.mu.Lock()
	defer a.mu.Unlock()
	c := a.cfg
	bc := b.Config
	c.RetentionDays = bc.RetentionDays
	c.AllowedEmails = bc.AllowedEmails
	c.Devices = bc.Devices
	c.Protected = bc.Protected
	c.BlockMinutes = bc.BlockMinutes
	c.MailTo = bc.MailTo
	c.MailMinLevel = bc.MailMinLevel
	c.FeedAllowed = bc.FeedAllowed
	c.MaxDailyMB = bc.MaxDailyMB
	c.LocalAnalysis = true
	c.AutoBlock = false
	if e = validateConfig(c); e != nil {
		return e
	}
	if email != "bootstrap" && !(a.demo && email == "demo@multipla-siem.local") {
		allowed := false
		for _, v := range c.AllowedEmails {
			if strings.EqualFold(v, email) {
				allowed = true
			}
		}
		if !allowed {
			return errors.New("backup removeria a autorização da conta atual")
		}
	}
	oldCfg, oldState := a.cfg, a.state
	prefs := map[string]Preferences{}
	for k, v := range a.state.Preferences {
		prefs[k] = v
	}
	prefs[strings.ToLower(email)] = b.Preferences
	if len(prefs) > 102 {
		return errors.New("limite de contas de preferências")
	}
	if e = atomicJSON(a.configPath, c); e != nil {
		return errors.New("não foi possível salvar configuração")
	}
	a.cfg = c
	a.state.Rules = b.Rules
	if b.NetworkEquipment != nil {
		a.state.NetworkEquipment = append([]NetworkEquipment{}, (*b.NetworkEquipment)...)
		a.state.SSHHostKeys = nil
	}
	a.state.Preferences = prefs
	if b.Receivers != nil {
		receivers := *b.Receivers
		receivers.InboundCredentials = oldState.Receivers.InboundCredentials
		receivers.OutboundCredentials = oldState.Receivers.OutboundCredentials
		receivers.OutboundURL = oldState.Receivers.OutboundURL
		for i, source := range receivers.Sources {
			for _, existing := range oldState.Receivers.Sources {
				if source.IP == existing.IP && source.Version == existing.Version && source.User == existing.User && source.EngineID == existing.EngineID {
					receivers.Sources[i].Credentials = existing.Credentials
				}
			}
		}
		clocks := map[string]SNMPClock{}
		for _, source := range receivers.Sources {
			if clock, ok := oldState.SNMPClocks[source.IP]; ok && clock.EngineID == source.EngineID {
				clocks[source.IP] = clock
			}
		}
		a.state.Receivers = receivers
		a.state.SNMPClocks = clocks
	}
	a.state.Audit = append([]Audit(nil), oldState.Audit...)
	a.audit(email, "backup restaurado; publicação de bloqueios desativada")
	if e = a.persist(); e != nil {
		a.cfg = oldCfg
		a.state = oldState
		if rollback := atomicJSON(a.configPath, oldCfg); rollback != nil {
			a.cfg = c
			a.cfg.AutoBlock = false
			a.storageError = "Restauração interrompida; confira configuração e estado antes de ativar respostas"
		}
		return errors.New("falha ao persistir restauração; verifique armazenamento")
	}
	a.receiverSecrets()
	a.analyzer = nil
	a.counters = map[string]bucket{}
	return nil
}
func (a *App) backupDirectory() string { return filepath.Join(a.cfg.DataDir, "backups") }
func (a *App) backupList(email string) ([]BackupEntry, error) {
	a.mu.Lock()
	dir := a.backupDirectory()
	a.mu.Unlock()
	entries, e := os.ReadDir(dir)
	if os.IsNotExist(e) {
		return []BackupEntry{}, nil
	}
	if e != nil {
		return nil, e
	}
	out := []BackupEntry{}
	for _, v := range entries {
		if !v.Type().IsRegular() || !backupName.MatchString(v.Name()) || !strings.HasPrefix(v.Name(), accountPrefix(email)) {
			continue
		}
		st, e := v.Info()
		if e != nil {
			continue
		}
		out = append(out, BackupEntry{v.Name(), st.ModTime().UTC(), st.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}
func (a *App) createLocalBackup(email string) ([]byte, error) {
	a.backupMu.Lock()
	defer a.backupMu.Unlock()
	a.mu.Lock()
	b := a.backupDocument(email)
	dir := a.backupDirectory()
	a.mu.Unlock()
	data, e := json.MarshalIndent(b, "", "  ")
	if e != nil || len(data) > backupLimit {
		return nil, errors.New("backup excede limite")
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	random := sha256.Sum256([]byte(token()))
	id := accountPrefix(email) + time.Now().UTC().Format("20060102150405.000000")
	id = strings.ReplaceAll(id, ".", "") + "-" + hex.EncodeToString(random[:8]) + ".json"
	if e = atomicJSON(filepath.Join(dir, id), b); e != nil {
		return nil, e
	}
	list, e := a.backupList(email)
	if e != nil {
		return nil, e
	}
	for i := 10; i < len(list); i++ {
		if e = os.Remove(filepath.Join(dir, list[i].ID)); e != nil {
			return nil, e
		}
	}
	return data, nil
}
func (a *App) readLocalBackup(email, id string) ([]byte, error) {
	if !backupName.MatchString(id) || !strings.HasPrefix(id, accountPrefix(email)) {
		return nil, errors.New("backup inválido para esta conta")
	}
	a.mu.Lock()
	path := filepath.Join(a.backupDirectory(), id)
	a.mu.Unlock()
	if e := regularFile(path); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, backupLimit+1))
	if e != nil || len(data) > backupLimit {
		return nil, errors.New("backup inválido")
	}
	return data, nil
}
func (a *App) registerBackupRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/preferences", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		p := a.preferences(s.Email)
		a.mu.Unlock()
		writeJSON(w, p)
	}))
	mux.HandleFunc("PUT /api/preferences", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var p Preferences
		if !decode(w, r, &p) {
			return
		}
		if e := validatePreferences(p); e != nil {
			http.Error(w, e.Error(), 400)
			return
		}
		s, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		if p.BackupDrive && a.state.DriveTokens[strings.ToLower(s.Email)] == "" {
			http.Error(w, "conecte o Google Drive antes de ativar o envio", 400)
			return
		}
		old, existed := a.state.Preferences[strings.ToLower(s.Email)]
		if a.state.Preferences == nil {
			a.state.Preferences = map[string]Preferences{}
		}
		if !existed && len(a.state.Preferences) >= 102 {
			http.Error(w, "limite de contas", 400)
			return
		}
		a.state.Preferences[strings.ToLower(s.Email)] = p
		if e := a.persist(); e != nil {
			if existed {
				a.state.Preferences[strings.ToLower(s.Email)] = old
			} else {
				delete(a.state.Preferences, strings.ToLower(s.Email))
			}
			http.Error(w, "falha ao salvar", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/backups", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		list, e := a.backupList(s.Email)
		if e != nil {
			http.Error(w, "falha na listagem", 500)
			return
		}
		a.mu.Lock()
		status := a.state.BackupStatus[strings.ToLower(s.Email)]
		a.mu.Unlock()
		writeJSON(w, map[string]any{"files": list, "status": status})
	}))
	mux.HandleFunc("GET /api/backup/export", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		b := a.backupDocument(s.Email)
		a.mu.Unlock()
		w.Header().Set("Content-Disposition", `attachment; filename="multipla-siem-backup.json"`)
		writeJSON(w, b)
	}))
	mux.HandleFunc("GET /api/backups/{id}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		data, e := a.readLocalBackup(s.Email, r.PathValue("id"))
		if e != nil {
			http.Error(w, "backup não encontrado", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="multipla-siem-backup.json"`)
		w.Write(data)
	}))
	mux.HandleFunc("POST /api/backup/create", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		data, e := a.createLocalBackup(s.Email)
		if e == nil {
			a.mu.Lock()
			drive := a.preferences(s.Email).BackupDrive
			a.mu.Unlock()
			if drive {
				e = a.uploadDriveBackup(s.Email, data)
			}
		}
		a.recordBackupStatus(s.Email, e)
		if e != nil {
			http.Error(w, e.Error(), 502)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/backup/import", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if !jsonContent(w, r) {
			return
		}
		s, _ := a.session(r)
		data, e := io.ReadAll(http.MaxBytesReader(w, r.Body, backupLimit))
		if e == nil {
			e = a.restoreBackup(s.Email, data)
		}
		if e != nil {
			http.Error(w, "Não restaurado: "+e.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/backups/{id}/restore", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		data, e := a.readLocalBackup(s.Email, r.PathValue("id"))
		if e == nil {
			e = a.restoreBackup(s.Email, data)
		}
		if e != nil {
			http.Error(w, "Não restaurado: "+e.Error(), 400)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	a.registerDriveRoutes(mux)
}

type BackupStatus struct {
	Day     string    `json:"day"`
	Attempt time.Time `json:"attempt"`
	Result  string    `json:"result"`
}

func (a *App) recordBackupStatus(email string, e error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	key := strings.ToLower(email)
	s := a.state.BackupStatus[key]
	s.Attempt = time.Now().UTC()
	s.Result = "Backup local concluído"
	if a.preferences(email).BackupDrive {
		s.Result = "Backup local e Drive concluídos"
	}
	if e != nil {
		s.Result = "Falha: " + redact(e.Error())
	}
	a.state.BackupStatus[key] = s
	a.audit(email, s.Result)
	if err := a.persist(); err != nil {
		a.storageError = "Falha ao registrar resultado do backup"
	}
}
func (a *App) runScheduledBackups(now time.Time) {
	a.mu.Lock()
	var due []string
	for email, p := range a.state.Preferences {
		if !p.BackupDaily {
			continue
		}
		allowed := email == "bootstrap"
		for _, v := range a.cfg.AllowedEmails {
			if strings.EqualFold(v, email) {
				allowed = true
			}
		}
		if !allowed {
			continue
		}
		loc, e := time.LoadLocation(p.BackupTimezone)
		if e != nil {
			continue
		}
		local := now.In(loc)
		day := local.Format("2006-01-02")
		if local.Format("15:04") < p.BackupTime || a.state.BackupStatus[email].Day == day {
			continue
		}
		old := a.state.BackupStatus[email]
		next := old
		next.Day = day
		a.state.BackupStatus[email] = next
		if e = a.persist(); e != nil {
			a.state.BackupStatus[email] = old
			a.storageError = "Falha ao registrar agendamento"
			continue
		}
		due = append(due, email)
	}
	a.mu.Unlock()
	for _, email := range due {
		data, e := a.createLocalBackup(email)
		a.mu.Lock()
		drive := a.preferences(email).BackupDrive
		a.mu.Unlock()
		if e == nil && drive {
			e = a.uploadDriveBackup(email, data)
		}
		a.recordBackupStatus(email, e)
	}
}
func (a *App) backupScheduler() {
	for now := range time.Tick(time.Minute) {
		a.runScheduledBackups(now)
	}
}
