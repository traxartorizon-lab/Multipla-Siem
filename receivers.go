package main

import (
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
)

type SNMPSource struct {
	Name        string `json:"name"`
	IP          string `json:"ip"`
	Version     string `json:"version"`
	User        string `json:"user,omitempty"`
	EngineID    string `json:"engine_id,omitempty"`
	Credentials string `json:"credentials_encrypted,omitempty"`
}
type ReceiverSettings struct {
	SNMPEnabled         bool         `json:"snmp_enabled"`
	Sources             []SNMPSource `json:"snmp_sources"`
	InboundEnabled      bool         `json:"inbound_enabled"`
	InboundIPs          []string     `json:"inbound_ips"`
	InboundCredentials  string       `json:"inbound_credentials_encrypted,omitempty"`
	OutboundEnabled     bool         `json:"outbound_enabled"`
	OutboundURL         string       `json:"outbound_url"`
	OutboundIP          string       `json:"outbound_allowed_ip,omitempty"`
	OutboundLevel       int          `json:"outbound_min_level"`
	OutboundCredentials string       `json:"outbound_credentials_encrypted,omitempty"`
}

var receiverRedactions atomic.Pointer[[]string]

func (a *App) receiverSecrets() {
	values := []string{}
	if secret, e := openDriveToken("n8n", a.state.N8N.Credentials); e == nil {
		values = append(values, secret.Access)
	}
	for _, source := range a.state.Receivers.Sources {
		if secret, e := openDriveToken("snmp:"+source.IP, source.Credentials); e == nil {
			values = append(values, secret.Access, secret.Refresh, secret.Scope)
		}
	}
	for _, v := range []struct{ key, value string }{{"webhook-in", a.state.Receivers.InboundCredentials}, {"webhook-out", a.state.Receivers.OutboundCredentials}} {
		if secret, e := openDriveToken(v.key, v.value); e == nil {
			values = append(values, secret.Access)
		}
	}
	receiverRedactions.Store(&values)
}

func sourceAddress(value string) bool {
	ip, err := netip.ParseAddr(value)
	return err == nil && ip.Unmap().String() == value && !ip.IsUnspecified() && !ip.IsMulticast()
}

func validateReceivers(settings ReceiverSettings) error {
	if len(settings.Sources) > 64 || len(settings.InboundIPs) > 64 || len(settings.OutboundURL) > 2048 {
		return errors.New("limite de configuração excedido")
	}
	seen := map[string]bool{}
	for _, source := range settings.Sources {
		if source.Name == "" || len(source.Name) > 80 || strings.ContainsAny(source.Name, "\r\n\x00") || !sourceAddress(source.IP) || seen[source.IP] || (source.Version != "v2c" && source.Version != "v3") || len(source.Credentials) > 12000 {
			return errors.New("origem SNMP inválida")
		}
		seen[source.IP] = true
		if source.Version == "v3" {
			engine, err := hex.DecodeString(source.EngineID)
			if err != nil || len(engine) < 5 || len(engine) > 32 || len(source.User) < 1 || len(source.User) > 32 || strings.ContainsAny(source.User, "\r\n\x00") {
				return errors.New("SNMPv3 exige usuário e engine ID hexadecimal de 5 a 32 bytes")
			}
		}
	}
	for _, ip := range settings.InboundIPs {
		if !sourceAddress(ip) {
			return errors.New("IP de webhook inválido")
		}
	}
	if settings.InboundEnabled && (len(settings.InboundIPs) == 0 || settings.InboundCredentials == "") {
		return errors.New("webhook de entrada exige token e IPs autorizados")
	}
	if settings.OutboundLevel < 0 || settings.OutboundLevel > 15 {
		return errors.New("nível inválido")
	}
	if settings.OutboundEnabled {
		if err := validateWebhookURL(settings.OutboundURL, settings.OutboundIP); err != nil {
			return err
		}
	}
	return nil
}

func (a *App) registerReceiverRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/receivers", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		settings := a.state.Receivers
		settings.Sources = append([]SNMPSource{}, settings.Sources...)
		for i := range settings.Sources {
			settings.Sources[i].Credentials = ""
		}
		settings.InboundCredentials = ""
		settings.OutboundCredentials = ""
		writeJSON(w, map[string]any{"settings": settings, "syslog_address": a.cfg.Syslog, "snmp_address": a.snmpAddress(), "snmp_status": a.snmpStatus, "outbound_status": a.webhookStatus})
	}))
	mux.HandleFunc("PUT /api/receivers/snmp", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Enabled bool `json:"enabled"`
			Sources []struct {
				Name            string `json:"name"`
				IP              string `json:"ip"`
				Version         string `json:"version"`
				User            string `json:"user"`
				EngineID        string `json:"engine_id"`
				Community       string `json:"community"`
				AuthPassword    string `json:"auth_password"`
				PrivacyPassword string `json:"privacy_password"`
			} `json:"sources"`
		}
		if !decode(w, r, &input) {
			return
		}
		if len(input.Sources) > 64 {
			http.Error(w, "máximo 64 origens", 400)
			return
		}
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		old := a.state.Receivers
		updated := old
		updated.Sources = []SNMPSource{}
		updated.SNMPEnabled = input.Enabled
		for _, v := range input.Sources {
			source := SNMPSource{Name: v.Name, IP: v.IP, Version: v.Version, User: v.User, EngineID: strings.NewReplacer(":", "", " ", "").Replace(strings.TrimPrefix(strings.ToLower(v.EngineID), "0x"))}
			if v.Version == "v2c" {
				source.User = ""
				source.EngineID = ""
				v.User = ""
				v.EngineID = ""
				v.AuthPassword = ""
				v.PrivacyPassword = ""
			}
			if v.Community == "" && v.AuthPassword == "" && v.PrivacyPassword == "" {
				for _, existing := range old.Sources {
					if existing.IP == v.IP && existing.Version == v.Version && existing.User == v.User && existing.EngineID == source.EngineID {
						source.Credentials = existing.Credentials
					}
				}
			}
			if v.Version == "v3" {
				v.Community = ""
			}
			if source.Credentials == "" {
				if (v.Version == "v2c" && (len(v.Community) < 16 || len(v.Community) > 128)) || (v.Version == "v3" && (len(v.AuthPassword) < 12 || len(v.AuthPassword) > 128 || len(v.PrivacyPassword) < 12 || len(v.PrivacyPassword) > 128)) {
					http.Error(w, "v2c exige community de 16 a 128 caracteres; v3 exige duas senhas de 12 a 128 caracteres", 400)
					return
				}
				cipher, err := sealDriveToken("snmp:"+v.IP, DriveToken{Access: v.Community, Refresh: v.AuthPassword, Scope: v.PrivacyPassword})
				if err != nil {
					http.Error(w, "chave de proteção ausente", 503)
					return
				}
				source.Credentials = cipher
			}
			updated.Sources = append(updated.Sources, source)
		}
		if err := validateReceivers(updated); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.audit(session.Email, "configuração de receptores atualizada")
		a.state.Receivers = updated
		oldClocks := a.state.SNMPClocks
		keptClocks := map[string]SNMPClock{}
		for _, source := range updated.Sources {
			if clock, ok := oldClocks[source.IP]; ok && clock.EngineID == source.EngineID {
				keptClocks[source.IP] = clock
			}
		}
		a.state.SNMPClocks = keptClocks
		if err := a.persist(); err != nil {
			a.state.Receivers = old
			a.state.SNMPClocks = oldClocks
			http.Error(w, "falha ao salvar", 503)
			return
		}
		a.receiverSecrets()
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("PUT /api/receivers/webhook", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			InboundEnabled  bool     `json:"inbound_enabled"`
			IPs             []string `json:"inbound_ips"`
			Rotate          bool     `json:"rotate_token"`
			OutboundEnabled bool     `json:"outbound_enabled"`
			URL             string   `json:"outbound_url"`
			AllowedIP       string   `json:"outbound_allowed_ip"`
			Level           int      `json:"outbound_min_level"`
			Secret          string   `json:"outbound_secret"`
		}
		if !decode(w, r, &input) {
			return
		}
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		old := a.state.Receivers
		updated := old
		generated := ""
		updated.InboundEnabled = input.InboundEnabled
		updated.InboundIPs = input.IPs
		updated.OutboundEnabled = input.OutboundEnabled
		updated.OutboundURL = input.URL
		updated.OutboundIP = input.AllowedIP
		updated.OutboundLevel = input.Level
		if input.Rotate || (input.InboundEnabled && updated.InboundCredentials == "") {
			generated = token()
			cipher, err := sealDriveToken("webhook-in", DriveToken{Access: generated})
			if err != nil {
				http.Error(w, "chave de proteção ausente", 503)
				return
			}
			updated.InboundCredentials = cipher
		}
		if input.Secret != "" {
			if len(input.Secret) < 32 || len(input.Secret) > 256 {
				http.Error(w, "segredo HMAC deve ter 32 a 256 caracteres", 400)
				return
			}
			cipher, err := sealDriveToken("webhook-out", DriveToken{Access: input.Secret})
			if err != nil {
				http.Error(w, "chave de proteção ausente", 503)
				return
			}
			updated.OutboundCredentials = cipher
		}
		if updated.OutboundEnabled && updated.OutboundCredentials == "" {
			http.Error(w, "informe o segredo HMAC", 400)
			return
		}
		if err := validateReceivers(updated); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.audit(session.Email, "configuração de receptores atualizada")
		a.state.Receivers = updated
		if err := a.persist(); err != nil {
			a.state.Receivers = old
			http.Error(w, "falha ao salvar", 503)
			return
		}
		a.receiverSecrets()
		writeJSON(w, map[string]string{"token": generated})
	}))
	mux.HandleFunc("POST /api/events/webhook", a.receiveWebhook)
}
