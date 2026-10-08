package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const n8nQueueLimit = 128

type N8NSettings struct {
	Mode        string    `json:"mode"`
	URL         string    `json:"url"`
	AllowedIP   string    `json:"allowed_ip,omitempty"`
	MinLevel    int       `json:"min_level"`
	Enabled     bool      `json:"enabled"`
	Credentials string    `json:"credentials_encrypted,omitempty"`
	Revision    string    `json:"revision,omitempty"`
	Verified    string    `json:"verified,omitempty"`
	Status      string    `json:"status,omitempty"`
	LastSuccess time.Time `json:"last_success,omitempty"`
	LastFailure time.Time `json:"last_failure,omitempty"`
	Delivered   uint64    `json:"delivered"`
	Failed      uint64    `json:"failed"`
}

// The durable queue deliberately contains no raw logs or credentials.
type N8NPayload struct {
	Schema   int       `json:"schema"`
	Product  string    `json:"product"`
	Version  string    `json:"version"`
	Kind     string    `json:"kind"`
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Device   string    `json:"device"`
	Protocol string    `json:"protocol"`
	SourceIP string    `json:"source_ip"`
	Level    int       `json:"level"`
	Title    string    `json:"title"`
}
type N8NDelivery struct {
	Payload  N8NPayload `json:"payload"`
	Revision string     `json:"revision"`
	Attempts int        `json:"attempts"`
	Next     time.Time  `json:"next"`
	Created  time.Time  `json:"created"`
}

func validateN8N(s N8NSettings) error {
	if s.Mode == "" && !s.Enabled && s.URL == "" {
		return nil
	}
	if s.Mode != "cloud" && s.Mode != "self_hosted" {
		return errors.New("escolha n8n Cloud ou servidor próprio")
	}
	if s.MinLevel < 1 || s.MinLevel > 15 {
		return errors.New("nível deve ser de 1 a 15")
	}
	if s.Mode == "cloud" && s.AllowedIP != "" {
		return errors.New("n8n Cloud não utiliza IP privado autorizado")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(s.URL) > 2048 || strings.ContainsAny(u.Hostname(), "%\r\n") {
		return errors.New("URL n8n exige HTTPS, sem usuário, query ou fragmento")
	}
	// Reuse URL syntax restrictions while validating IP scope separately.
	syntaxURL := *u
	syntaxURL.Host = "example.com"
	if u.Port() != "" {
		syntaxURL.Host = net.JoinHostPort("example.com", u.Port())
	}
	if u.Hostname() == "" || validateWebhookURL(syntaxURL.String(), "") != nil {
		return errors.New("URL n8n inválida")
	}
	if !strings.HasPrefix(u.Path, "/webhook/") || len(strings.TrimPrefix(u.Path, "/webhook/")) == 0 {
		return errors.New("cole a Production URL do Webhook n8n, contendo /webhook/; URL de teste não é aceita")
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." || strings.ContainsAny(segment, "\\\r\n\x00") {
			return errors.New("caminho do Webhook inválido")
		}
	}
	if s.AllowedIP != "" {
		ip, e := netip.ParseAddr(s.AllowedIP)
		if e != nil || ip.Unmap().String() != s.AllowedIP || !n8nPrivateIP(ip) {
			return errors.New("autorize um IP privado ou Tailscale exato, sem faixa CIDR")
		}
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !n8nIPAllowed(ip, s.AllowedIP) {
		return errors.New("IP n8n não autorizado")
	}
	if s.Enabled && (s.Credentials == "" || s.Revision == "" || s.Verified != s.Revision) {
		return errors.New("salve a configuração e teste a conexão antes de ativar")
	}
	return nil
}

func n8nPrivateIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsUnspecified() && (ip.IsPrivate() || (netip.MustParsePrefix("100.64.0.0/10").Contains(ip) && ip.String() != "100.100.100.100" && ip.String() != "100.100.100.200"))
}
func n8nIPAllowed(ip netip.Addr, approved string) bool {
	return webhookIPAllowed(ip, "") || (ip.Unmap().String() == approved && n8nPrivateIP(ip))
}

func n8nClient(approved string) *http.Client {
	c := webhookClient("")
	t := c.Transport.(*http.Transport)
	t.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			return nil, errors.New("destino n8n indisponível")
		}
		for _, ip := range ips {
			if !n8nIPAllowed(ip, approved) {
				return nil, errors.New("destino n8n não autorizado")
			}
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return c
}

type n8nHTTPError struct{ Code int }

func (e n8nHTTPError) Error() string {
	switch e.Code {
	case 401, 403:
		return fmt.Sprintf("n8n respondeu HTTP %d; confira a credencial Header Auth, X-Multipla-Token e a lista de IPs permitidos", e.Code)
	case 404:
		return "n8n respondeu HTTP 404; publique/ative o fluxo e confira a Production URL"
	case 429:
		return "n8n respondeu HTTP 429; limite de requisições atingido"
	default:
		return fmt.Sprintf("n8n respondeu HTTP %d; confira o fluxo e o proxy de destino", e.Code)
	}
}

func deliverN8N(ctx context.Context, s N8NSettings, p N8NPayload, client *http.Client) error {
	if err := validateN8N(s); err != nil {
		return err
	}
	secret, err := openDriveToken("n8n", s.Credentials)
	if err != nil {
		return errors.New("credencial n8n indisponível")
	}
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	r, err := http.NewRequestWithContext(ctx, "POST", s.URL, bytes.NewReader(body))
	if err != nil {
		return errors.New("URL n8n inválida")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-Multipla-Token", secret.Access)
	r.Header.Set("X-Multipla-Timestamp", fmt.Sprint(time.Now().Unix()))
	r.Header.Set("X-Multipla-Event-ID", p.ID)
	res, err := client.Do(r)
	if err != nil {
		return errors.New("conexão n8n falhou; confira HTTPS, certificado, DNS e permissões de rede")
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return n8nHTTPError{res.StatusCode}
	}
	var ack struct {
		OK     bool   `json:"ok"`
		ID     string `json:"id"`
		Schema int    `json:"schema"`
		Kind   string `json:"kind"`
	}
	dec := json.NewDecoder(io.LimitReader(res.Body, 4096))
	if dec.Decode(&ack) != nil || !ack.OK || ack.ID != p.ID || ack.Schema != 1 || ack.Kind != p.Kind {
		return errors.New("n8n não confirmou o evento; importe o fluxo Multipla e confira o Respond to Webhook")
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("resposta n8n inválida")
	}
	return nil
}

// Called with a.mu held, after the local event has been recorded.
func (a *App) queueN8N(e Event) {
	s := a.state.N8N
	if a.demo || !s.Enabled || !e.Alert || e.Level < s.MinLevel || e.Protocol == "webhook" || e.Kind == "webhook" {
		return
	}
	if len(a.state.N8NOutbox) >= n8nQueueLimit {
		a.state.N8N.Failed++
		a.state.N8N.Status = "Fila n8n cheia; alerta permanece no histórico local"
		a.audit("n8n", "fila cheia; notificação não enfileirada")
		_ = a.persist()
		return
	}
	old := append([]N8NDelivery(nil), a.state.N8NOutbox...)
	p := N8NPayload{1, "Multipla Siem", productVersion(), "alert", e.ID, e.Time, n8nText(e.Device, 256), n8nText(e.Protocol, 64), n8nText(e.SourceIP, 64), e.Level, n8nText(e.Rule, 1024)}
	now := time.Now().UTC()
	a.state.N8NOutbox = append(a.state.N8NOutbox, N8NDelivery{Payload: p, Revision: s.Revision, Next: now, Created: now})
	if err := a.persist(); err != nil {
		a.state.N8NOutbox = old
		a.state.N8N.Status = "Falha ao gravar fila n8n; alerta permanece no histórico local"
	}
}

func n8nText(value string, limit int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, redact(value))
	runes := []rune(value)
	if len(runes) > limit {
		value = string(runes[:limit])
	}
	return value
}

func (a *App) n8nWorker() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		a.processN8N(time.Now().UTC(), nil)
	}
}

func (a *App) processN8N(now time.Time, client *http.Client) {
	a.mu.Lock()
	if a.demo || !a.state.N8N.Enabled || len(a.state.N8NOutbox) == 0 {
		a.mu.Unlock()
		return
	}
	d := a.state.N8NOutbox[0]
	s := a.state.N8N
	if d.Next.After(now) {
		a.mu.Unlock()
		return
	}
	// Persist the attempt before transmission so crashes cannot reset the retry budget.
	old := d
	a.state.N8NOutbox[0].Attempts++
	a.state.N8NOutbox[0].Next = now.Add(30 * time.Second)
	if err := a.persist(); err != nil {
		a.state.N8NOutbox[0] = old
		a.state.N8N.Status = "Fila indisponível; envio suspenso"
		a.mu.Unlock()
		return
	}
	d = a.state.N8NOutbox[0]
	a.mu.Unlock()
	var err error
	if d.Revision != s.Revision || now.Sub(d.Created) > 24*time.Hour || d.Attempts > 6 {
		err = errors.New("notificação expirada ou configuração alterada")
	} else {
		if client == nil {
			client = n8nClient(s.AllowedIP)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err = deliverN8N(ctx, s, d.Payload, client)
		cancel()
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.N8N.Revision != s.Revision || len(a.state.N8NOutbox) == 0 || a.state.N8NOutbox[0].Payload.ID != d.Payload.ID {
		return
	}
	previousSettings := a.state.N8N
	previousQueue := append([]N8NDelivery(nil), a.state.N8NOutbox...)
	var statusErr n8nHTTPError
	permanent := errors.As(err, &statusErr) && statusErr.Code >= 400 && statusErr.Code < 500 && statusErr.Code != 408 && statusErr.Code != 429
	if err == nil {
		a.state.N8NOutbox = a.state.N8NOutbox[1:]
		a.state.N8N.Delivered++
		a.state.N8N.LastSuccess = now
		a.state.N8N.Status = "Evento confirmado pelo n8n"
	} else if permanent || d.Attempts >= 6 || now.Sub(d.Created) > 24*time.Hour || d.Revision != s.Revision {
		a.state.N8NOutbox = a.state.N8NOutbox[1:]
		a.state.N8N.Failed++
		a.state.N8N.LastFailure = now
		a.state.N8N.Status = "Envio encerrado: " + err.Error()
		a.audit("n8n", a.state.N8N.Status)
	} else {
		a.state.N8NOutbox[0].Next = now.Add(time.Duration(1<<uint(d.Attempts)) * 15 * time.Second)
		a.state.N8N.LastFailure = now
		a.state.N8N.Status = "Nova tentativa agendada: " + err.Error()
	}
	if a.persist() != nil {
		a.state.N8N = previousSettings
		a.state.N8NOutbox = previousQueue
		a.state.N8N.Status = "Falha ao salvar confirmação; entrega pode ser repetida com o mesmo ID"
	}
}

func (a *App) registerN8NRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/integrations/n8n", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		s := a.state.N8N
		configured := s.Credentials != ""
		s.Credentials = ""
		s.Revision = ""
		s.Verified = ""
		writeJSON(w, map[string]any{"settings": s, "has_token": configured, "tested": a.state.N8N.Revision != "" && a.state.N8N.Verified == a.state.N8N.Revision, "pending": len(a.state.N8NOutbox)})
	}))
	mux.HandleFunc("GET /api/integrations/n8n/workflow", a.auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="multipla-siem-n8n.json"`)
		writeJSON(w, n8nWorkflow())
	}))
	mux.HandleFunc("PUT /api/integrations/n8n", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Mode    string `json:"mode"`
			URL     string `json:"url"`
			IP      string `json:"allowed_ip"`
			Level   int    `json:"min_level"`
			Enabled bool   `json:"enabled"`
			Token   string `json:"token"`
		}
		if !decode(w, r, &input) {
			return
		}
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.demo {
			http.Error(w, "integrações desativadas na demonstração", 403)
			return
		}
		old := a.state.N8N
		oldQueue := a.state.N8NOutbox
		s := old
		s.Mode = input.Mode
		s.URL = strings.TrimSpace(input.URL)
		s.AllowedIP = strings.TrimSpace(input.IP)
		s.MinLevel = input.Level
		s.Enabled = input.Enabled
		changed := old.Mode != s.Mode || old.URL != s.URL || old.AllowedIP != s.AllowedIP || input.Token != ""
		if input.Token != "" {
			if len(input.Token) < 32 || len(input.Token) > 256 || strings.ContainsAny(input.Token, "\r\n\x00") {
				http.Error(w, "token exige 32 a 256 caracteres, sem quebras de linha", 400)
				return
			}
			cipher, e := sealDriveToken("n8n", DriveToken{Access: input.Token})
			if e != nil {
				http.Error(w, "chave de proteção indisponível", 503)
				return
			}
			s.Credentials = cipher
		}
		if changed || s.Revision == "" {
			s.Revision = token()
			s.Verified = ""
			s.Status = "Configuração salva; teste a conexão"
		}
		if s.Credentials == "" {
			http.Error(w, "gere e cadastre a credencial do n8n", 400)
			return
		}
		if err := validateN8N(s); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		a.state.N8N = s
		if changed || !s.Enabled {
			a.state.N8NOutbox = nil
		}
		a.audit(session.Email, "integração n8n configurada; credencial omitida")
		if a.persist() != nil {
			a.state.N8N = old
			a.state.N8NOutbox = oldQueue
			http.Error(w, "falha ao salvar integração", 503)
			return
		}
		a.receiverSecrets()
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/integrations/n8n/test", a.auth(func(w http.ResponseWriter, r *http.Request) {
		session, _ := a.session(r)
		a.mu.Lock()
		if a.demo || a.n8nTestBusy || time.Since(a.n8nTestLast) < 10*time.Second {
			a.mu.Unlock()
			http.Error(w, "aguarde antes de repetir o teste", 429)
			return
		}
		s := a.state.N8N
		if s.Credentials == "" || validateN8N(s) != nil {
			a.mu.Unlock()
			http.Error(w, "salve a configuração antes do teste", 400)
			return
		}
		a.n8nTestBusy = true
		a.n8nTestLast = time.Now()
		a.mu.Unlock()
		p := N8NPayload{Schema: 1, Product: "Multipla Siem", Version: productVersion(), Kind: "test", ID: token(), Time: time.Now().UTC(), Title: "Teste de conexão; não executar automações", Level: 1}
		err := deliverN8N(r.Context(), s, p, n8nClient(s.AllowedIP))
		a.mu.Lock()
		defer a.mu.Unlock()
		a.n8nTestBusy = false
		if a.state.N8N.Revision != s.Revision {
			http.Error(w, "configuração mudou durante o teste; teste novamente", 409)
			return
		}
		previous := a.state.N8N
		a.state.N8N.Verified = ""
		if err == nil {
			a.state.N8N.Verified = s.Revision
			a.state.N8N.Status = "Conexão testada; fluxo confirmou o teste sem automações"
		} else {
			a.state.N8N.Status = "Teste falhou: " + err.Error()
			a.state.N8N.Enabled = false
		}
		a.audit(session.Email, a.state.N8N.Status)
		if a.persist() != nil {
			a.state.N8N = previous
			http.Error(w, "falha ao salvar resultado", 503)
			return
		}
		if err != nil {
			http.Error(w, a.state.N8N.Status, 502)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
