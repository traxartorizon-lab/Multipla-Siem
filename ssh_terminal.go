package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHHostIdentity struct {
	IP          string `json:"ip"`
	Port        int    `json:"port"`
	Key         string `json:"key"`
	Fingerprint string `json:"fingerprint"`
}
type sshTerminal struct {
	mu                         sync.Mutex
	inputMu                    sync.Mutex
	id, owner, status, message string
	equipment                  NetworkEquipment
	client                     *ssh.Client
	session                    *ssh.Session
	input                      io.WriteCloser
	output                     []byte
	base                       int64
	lastRead                   time.Time
	cancel                     context.CancelFunc
}

var sshDial = func(ctx context.Context, address string) (net.Conn, error) {
	return (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, "tcp", address)
}
var sshProbeSlots = make(chan struct{}, 2)

const localServerSSHID = "__multipla_local_server__"

func sshEquipmentAddress(d NetworkEquipment) string {
	port := d.SSHPort
	if port == 0 {
		port = 22
	}
	return net.JoinHostPort(d.IP, strconv.Itoa(port))
}
func sshEquipmentUser(d NetworkEquipment) string {
	if d.SSHUser != "" {
		return d.SSHUser
	}
	if d.Kind == "pfsense" {
		return "admin"
	}
	return "root"
}
func probeSSHIdentity(ctx context.Context, d NetworkEquipment) (SSHHostIdentity, error) {
	select {
	case sshProbeSlots <- struct{}{}:
		defer func() { <-sshProbeSlots }()
	default:
		return SSHHostIdentity{}, errors.New("há verificações SSH em andamento; tente novamente")
	}
	conn, err := sshDial(ctx, sshEquipmentAddress(d))
	if err != nil {
		return SSHHostIdentity{}, sshReachabilityError(d, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(8 * time.Second))
	var key ssh.PublicKey
	config := &ssh.ClientConfig{User: sshEquipmentUser(d), HostKeyCallback: func(_ string, _ net.Addr, k ssh.PublicKey) error {
		key = k
		return errors.New("verificação pública da identificação; autenticação não solicitada")
	}}
	_, _, _, _ = ssh.NewClientConn(conn, sshEquipmentAddress(d), config)
	if key == nil {
		return SSHHostIdentity{}, errors.New("não foi possível verificar a identificação SSH")
	}
	port := d.SSHPort
	if port == 0 {
		port = 22
	}
	return SSHHostIdentity{d.IP, port, base64.StdEncoding.EncodeToString(key.Marshal()), ssh.FingerprintSHA256(key)}, nil
}
func (a *App) sshEquipment(id string) (NetworkEquipment, error) {
	if id == localServerSSHID {
		return NetworkEquipment{ID: localServerSSHID, Name: "Servidor SIEM", IP: "127.0.0.1", Kind: "server", SSHPort: 22, Client: "Manutenção", Unit: "Servidor local"}, nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range a.state.NetworkEquipment {
		if d.ID == id && (d.Kind == "pfsense" || d.Kind == "proxmox") {
			return d, nil
		}
	}
	return NetworkEquipment{}, errors.New("cadastre e selecione um pfSense ou Proxmox por cliente e unidade")
}
func (a *App) getSSHTerminal(r *http.Request) (*sshTerminal, bool) {
	session, ok := a.session(r)
	if !ok {
		return nil, false
	}
	a.mu.Lock()
	t := a.sshTerminals[r.PathValue("id")]
	a.mu.Unlock()
	if t != nil && t.equipment.ID == localServerSSHID && !a.hostSuperadmin(r) {
		return nil, false
	}
	return t, t != nil && t.owner == strings.ToLower(session.Email)
}
func (t *sshTerminal) Write(data []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.output = append(t.output, data...)
	if len(t.output) > 1<<20 {
		discard := len(t.output) - (1 << 20)
		t.output = t.output[discard:]
		t.base += int64(discard)
	}
	return len(data), nil
}
func (t *sshTerminal) close(message string) {
	t.mu.Lock()
	if t.status == "closed" {
		t.mu.Unlock()
		return
	}
	t.status = "closed"
	t.message = message
	client := t.client
	session := t.session
	t.mu.Unlock()
	t.cancel()
	if session != nil {
		session.Close()
	}
	if client != nil {
		client.Close()
	}
}
func (a *App) connectSSHTerminal(ctx context.Context, t *sshTerminal, auth ssh.AuthMethod, key ssh.PublicKey) {
	conn, err := sshDial(ctx, sshEquipmentAddress(t.equipment))
	if err != nil {
		t.close(sshReachabilityError(t.equipment, err).Error())
		return
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	stopDeadline := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopDeadline()
	config := &ssh.ClientConfig{User: sshEquipmentUser(t.equipment), Auth: []ssh.AuthMethod{auth}, HostKeyCallback: ssh.FixedHostKey(key)}
	c, channels, requests, err := ssh.NewClientConn(conn, sshEquipmentAddress(t.equipment), config)
	config.Auth = nil
	auth = nil
	if err != nil {
		conn.Close()
		t.close("Conexão rejeitada: confira a credencial, o usuário e a identificação SSH cadastrada.")
		return
	}
	conn.SetDeadline(time.Time{})
	client := ssh.NewClient(c, channels, requests)
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		t.close("O servidor não permitiu abrir uma sessão.")
		return
	}
	input, err := session.StdinPipe()
	if err != nil {
		session.Close()
		client.Close()
		t.close("Não foi possível abrir o terminal.")
		return
	}
	session.Stdout = t
	session.Stderr = t
	if err = session.RequestPty("xterm-256color", 28, 100, ssh.TerminalModes{ssh.ECHO: 1, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}); err != nil {
		session.Close()
		client.Close()
		t.close("O servidor não permitiu um terminal interativo.")
		return
	}
	t.mu.Lock()
	if t.status == "closed" {
		t.mu.Unlock()
		session.Close()
		client.Close()
		return
	}
	t.client = client
	t.session = session
	t.input = input
	t.mu.Unlock()
	if err = session.Shell(); err != nil {
		t.close("Não foi possível iniciar o shell remoto.")
		return
	}
	t.mu.Lock()
	if t.status != "closed" {
		t.status = "connected"
	}
	t.mu.Unlock()
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				t.close("Sessão encerrada: prazo de 30 minutos ou desconexão.")
				return
			case <-ticker.C:
				t.mu.Lock()
				idle := time.Since(t.lastRead) > 2*time.Minute
				t.mu.Unlock()
				if idle {
					t.close("Sessão encerrada por ausência do navegador.")
					return
				}
			}
		}
	}()
	session.Wait()
	t.close("Sessão SSH encerrada.")
}
func (a *App) registerSSHRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/ssh/identity", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if a.demo {
			http.Error(w, "SSH real indisponível na demonstração", 503)
			return
		}
		var body struct {
			ID string `json:"id"`
		}
		if !decode(w, r, &body) {
			return
		}
		if body.ID == localServerSSHID && !a.hostSuperadmin(r) {
			http.Error(w, "Terminal do servidor exige Superadmin", 403)
			return
		}
		d, err := a.sshEquipment(body.ID)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		identity, err := probeSSHIdentity(r.Context(), d)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		a.mu.Lock()
		known := a.state.SSHHostKeys[d.ID]
		a.mu.Unlock()
		writeJSON(w, map[string]any{"identity": identity, "trusted": known == identity, "previous_fingerprint": known.Fingerprint})
	}))
	mux.HandleFunc("POST /api/ssh/trust", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if a.demo {
			http.Error(w, "SSH real indisponível na demonstração", 503)
			return
		}
		var body struct {
			ID  string `json:"id"`
			Key string `json:"key"`
		}
		if !decode(w, r, &body) {
			return
		}
		if len(body.Key) > 16384 {
			http.Error(w, "identificação inválida", 400)
			return
		}
		if body.ID == localServerSSHID && !a.hostSuperadmin(r) {
			http.Error(w, "Terminal do servidor exige Superadmin", 403)
			return
		}
		d, err := a.sshEquipment(body.ID)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		identity, err := probeSSHIdentity(r.Context(), d)
		if err != nil || identity.Key != body.Key {
			http.Error(w, "a identificação mudou; verifique novamente", 409)
			return
		}
		session, _ := a.session(r)
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.state.SSHHostKeys == nil {
			a.state.SSHHostKeys = map[string]SSHHostIdentity{}
		}
		old, exists := a.state.SSHHostKeys[d.ID]
		oldAudit := append([]Audit{}, a.state.Audit...)
		a.state.SSHHostKeys[d.ID] = identity
		a.audit(session.Email, "identificação SSH confirmada: "+d.Client+" / "+d.Unit+" / "+d.Name)
		if err := a.persist(); err != nil {
			if exists {
				a.state.SSHHostKeys[d.ID] = old
			} else {
				delete(a.state.SSHHostKeys, d.ID)
			}
			a.state.Audit = oldAudit
			http.Error(w, "falha ao salvar identificação", 500)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/ssh/sessions", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID         string `json:"id"`
			User       string `json:"user"`
			Password   string `json:"password"`
			PrivateKey string `json:"private_key"`
			Passphrase string `json:"passphrase"`
		}
		if !decode(w, r, &body) {
			return
		}
		if len(body.Password) > 4096 || len(body.PrivateKey) > 32768 || len(body.Passphrase) > 1024 {
			http.Error(w, "credencial excede o limite", 400)
			return
		}
		if body.ID == localServerSSHID && !a.hostSuperadmin(r) {
			http.Error(w, "Terminal do servidor exige Superadmin", 403)
			return
		}
		if a.demo || !a.nativeTLS {
			http.Error(w, "terminal SSH requer a instalação HTTPS; não disponível na demonstração", 503)
			return
		}

		d, err := a.sshEquipment(body.ID)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		if body.User != "" {
			d.SSHUser = strings.TrimSpace(body.User)
			valid := regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.@-]{0,63}$`).MatchString(d.SSHUser)
			if d.ID != localServerSSHID {
				valid = validateEquipment(d) == nil
			}
			if !valid {
				http.Error(w, "Usuário SSH inválido", 400)
				return
			}
		}
		if d.ID == localServerSSHID && d.SSHUser == "" {
			http.Error(w, "informe seu usuário Linux para acessar o servidor SIEM", 400)
			return
		}
		if body.PrivateKey != "" || body.Password != "" || body.Passphrase != "" {
			http.Error(w, "Credenciais pessoais não são aceitas; configure o SSH delegado por certificado", 400)
			return
		}
		a.mu.Lock()
		pinned := a.state.SSHHostKeys[d.ID]
		a.mu.Unlock()
		if pinned.Key == "" {
			http.Error(w, "verifique e confirme a identificação SSH antes de conectar", 409)
			return
		}
		principal, _ := a.session(r)
		method, err := delegatedSSHAuth(r.Context(), d, principal.Email)
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		current, validSession := a.session(r)
		if !validSession || current.Email != principal.Email {
			http.Error(w, "Sessão alterada durante a autorização SSH", 403)
			return
		}
		a.mu.Lock()
		identity := a.state.SSHHostKeys[d.ID]
		port := d.SSHPort
		if port == 0 {
			port = 22
		}
		raw, err := base64.StdEncoding.DecodeString(identity.Key)
		key, parseErr := ssh.ParsePublicKey(raw)
		if err != nil || parseErr != nil || identity.IP != d.IP || identity.Port != port {
			a.mu.Unlock()
			http.Error(w, "verifique e confirme a identificação SSH antes de conectar", 409)
			return
		}
		if a.sshTerminals == nil {
			a.sshTerminals = map[string]*sshTerminal{}
		}
		active := 0
		for id, t := range a.sshTerminals {
			t.mu.Lock()
			closed := t.status == "closed"
			t.mu.Unlock()
			if closed {
				delete(a.sshTerminals, id)
			} else {
				active++
			}
		}
		if active >= 4 {
			a.mu.Unlock()
			http.Error(w, "limite de quatro terminais; encerre uma sessão", 429)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		t := &sshTerminal{id: token(), owner: strings.ToLower(current.Email), equipment: d, status: "connecting", lastRead: time.Now(), cancel: cancel}
		oldAudit := append([]Audit{}, a.state.Audit...)
		a.audit(current.Email, "abertura de terminal SSH solicitada: "+d.Name+"; destino="+sshEquipmentAddress(d)+"; usuário="+d.SSHUser)
		if err := a.persist(); err != nil {
			a.state.Audit = oldAudit
			cancel()
			a.mu.Unlock()
			http.Error(w, "auditoria indisponível; terminal não iniciado", 503)
			return
		}
		a.sshTerminals[t.id] = t
		a.mu.Unlock()
		go a.connectSSHTerminal(ctx, t, method, key)
		writeJSON(w, map[string]any{"id": t.id, "equipment": d})
	}))
	mux.HandleFunc("GET /api/ssh/sessions/{id}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		t, ok := a.getSSHTerminal(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if err != nil || offset < 0 {
			http.Error(w, "posição inválida", 400)
			return
		}
		t.mu.Lock()
		defer t.mu.Unlock()
		t.lastRead = time.Now()
		next := t.base + int64(len(t.output))
		lost := offset < t.base
		if offset < t.base {
			offset = t.base
		}
		if offset > next {
			http.Error(w, "posição inválida", 400)
			return
		}
		out := t.output[offset-t.base:]
		if len(out) > 65536 {
			out = out[:65536]
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, map[string]any{"status": t.status, "message": t.message, "data": base64.StdEncoding.EncodeToString(out), "next": offset + int64(len(out)), "lost": lost})
	}))
	mux.HandleFunc("POST /api/ssh/sessions/{id}/input", a.auth(func(w http.ResponseWriter, r *http.Request) {
		t, ok := a.getSSHTerminal(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Data string `json:"data"`
		}
		if !decode(w, r, &body) {
			return
		}
		data, err := base64.StdEncoding.DecodeString(body.Data)
		if err != nil || len(data) > 4096 {
			http.Error(w, "entrada inválida", 400)
			return
		}
		t.mu.Lock()
		input, client := t.input, t.client
		connected := t.status == "connected"
		t.mu.Unlock()
		if input == nil || !connected {
			http.Error(w, "terminal desconectado", 409)
			return
		}
		t.inputMu.Lock()
		timer := time.AfterFunc(5*time.Second, func() { client.Close() })
		_, err = input.Write(data)
		timer.Stop()
		t.inputMu.Unlock()
		if err != nil {
			t.close("Falha ao transmitir a entrada.")
			http.Error(w, "terminal desconectado", 502)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/ssh/sessions/{id}/resize", a.auth(func(w http.ResponseWriter, r *http.Request) {
		t, ok := a.getSSHTerminal(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		var size struct {
			Cols int `json:"cols"`
			Rows int `json:"rows"`
		}
		if !decode(w, r, &size) {
			return
		}
		if size.Cols < 20 || size.Cols > 400 || size.Rows < 6 || size.Rows > 200 {
			http.Error(w, "dimensões do terminal inválidas", 400)
			return
		}
		t.mu.Lock()
		session, client, connected := t.session, t.client, t.status == "connected"
		t.lastRead = time.Now()
		t.mu.Unlock()
		if session == nil || client == nil || !connected {
			http.Error(w, "terminal desconectado", 409)
			return
		}
		t.inputMu.Lock()
		timer := time.AfterFunc(5*time.Second, func() { client.Close() })
		err := session.WindowChange(size.Rows, size.Cols)
		timer.Stop()
		t.inputMu.Unlock()
		if err != nil {
			t.close("Falha ao redimensionar o terminal.")
			http.Error(w, "terminal desconectado", 502)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/ssh/sessions/{id}/close", a.auth(func(w http.ResponseWriter, r *http.Request) {
		t, ok := a.getSSHTerminal(r)
		if !ok {
			http.NotFound(w, r)
			return
		}
		t.close("Sessão encerrada pelo operador.")
		a.mu.Lock()
		a.audit(t.owner, "terminal SSH encerrado pelo operador: "+t.equipment.Name)
		err := a.persist()
		a.mu.Unlock()
		if err != nil {
			http.Error(w, "terminal encerrado; falha ao persistir auditoria", 503)
			return
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}

func sshReachabilityError(d NetworkEquipment, err error) error {
	var detail string
	if errors.Is(err, context.DeadlineExceeded) {
		detail = "tempo de conexão esgotado; confira rota, regras de firewall e serviço SSH"
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		detail = "tempo de conexão esgotado; confira rota, regras de firewall e serviço SSH"
	} else {
		detail = "conexão recusada ou destino inacessível; confira IP, porta, rota e se o SSH está habilitado"
	}
	return fmt.Errorf("Não foi possível alcançar %s: %s. O teste parte do servidor SIEM", sshEquipmentAddress(d), detail)
}
