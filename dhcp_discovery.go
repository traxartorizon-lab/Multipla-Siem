package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type DHCPServer struct {
	IP        string `json:"ip"`
	Source    string `json:"source"`
	MAC       string `json:"mac"`
	Vendor    string `json:"vendor"`
	Network   string `json:"network"`
	Relay     bool   `json:"relay"`
	Responses int    `json:"responses"`
}
type dhcpJob struct {
	mu                                     sync.Mutex
	id, terminalID, owner, status, message string
	equipment                              NetworkEquipment
	started                                time.Time
	servers                                []DHCPServer
	diagnosis                              *ModelDiagnosis
	cancel                                 context.CancelFunc
}

var dhcpJobs = struct {
	sync.Mutex
	jobs map[string]*dhcpJob
}{jobs: map[string]*dhcpJob{}}
var dhcpSlots = make(chan struct{}, 2)
var localInferenceSlot = make(chan struct{}, 1)
var dhcpInterface = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.]{0,31}$`)

// The command is fixed. Only a tightly validated interface and bounded duration vary.
// The remote watchdog terminates capture even if the browser or SSH channel disappears.
func dhcpCaptureCommand(iface string, seconds int) (string, error) {
	if !dhcpInterface.MatchString(iface) || seconds < 10 || seconds > 120 {
		return "", errors.New("interface ou duração inválida")
	}
	script := fmt.Sprintf(`p=''; timer=''; cleanup(){ [ -z "$p" ] || kill -INT "$p" 2>/dev/null; [ -z "$timer" ] || kill "$timer" 2>/dev/null; }; trap cleanup EXIT HUP INT TERM; /usr/sbin/tcpdump -p -n -U -s 1500 -c 1000 -i %s -w - 'udp and src port 67 and (dst port 68 or dst port 67)' & p=$!; (sleep %d; kill -INT "$p" 2>/dev/null) & timer=$!; wait "$p"; code=$?; p=''; exit "$code"`, iface, seconds)
	return "/bin/sh -c '" + strings.ReplaceAll(script, "'", "'\"'\"'") + "'", nil
}

type limitedCapture struct {
	mu     sync.Mutex
	data   []byte
	limit  int
	cancel context.CancelFunc
}

func (b *limitedCapture) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.data)+len(p) > b.limit {
		b.cancel()
		return 0, errors.New("limite de captura atingido")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
func (b *limitedCapture) copy() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...)
}

// Parse only DHCP replies from a classic Ethernet PCAP. Packet text is never a prompt.
func parseDHCPCapture(data []byte) ([]DHCPServer, error) {
	if len(data) < 24 {
		return nil, errors.New("captura incompleta; confira interface e permissão tcpdump")
	}
	var order binary.ByteOrder
	switch string(data[:4]) {
	case "\xd4\xc3\xb2\xa1", "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4", "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
	default:
		return nil, errors.New("formato de captura não reconhecido")
	}
	if order.Uint16(data[4:6]) != 2 || order.Uint32(data[20:24]) != 1 {
		return nil, errors.New("selecione uma interface Ethernet; formato não suportado")
	}
	found := map[string]*DHCPServer{}
	for off := 24; off < len(data); {
		if len(data)-off < 16 {
			return nil, errors.New("registro de captura truncado")
		}
		size := int(order.Uint32(data[off+8 : off+12]))
		off += 16
		if size > 65535 || size > len(data)-off {
			return nil, errors.New("pacote de captura truncado")
		}
		p := data[off : off+size]
		off += size
		if len(p) < 14 {
			continue
		}
		mac := net.HardwareAddr(p[6:12]).String()
		etype := binary.BigEndian.Uint16(p[12:14])
		pos := 14
		for tags := 0; tags < 2 && (etype == 0x8100 || etype == 0x88a8); tags++ {
			if len(p) < pos+4 {
				break
			}
			etype = binary.BigEndian.Uint16(p[pos+2 : pos+4])
			pos += 4
		}
		if etype != 0x800 || len(p) < pos+20 {
			continue
		}
		ip := p[pos:]
		ihl := int(ip[0]&15) * 4
		if ip[0]>>4 != 4 || ihl < 20 || len(ip) < ihl+8 || ip[9] != 17 || binary.BigEndian.Uint16(ip[6:8])&0x3fff != 0 {
			continue
		}
		total := int(binary.BigEndian.Uint16(ip[2:4]))
		if total < ihl+8 || total > len(ip) {
			continue
		}
		ip = ip[:total]
		udp := ip[ihl:]
		ulen := int(binary.BigEndian.Uint16(udp[4:6]))
		if ulen < 8 || ulen > len(udp) || binary.BigEndian.Uint16(udp[:2]) != 67 {
			continue
		}
		dest := binary.BigEndian.Uint16(udp[2:4])
		if dest != 67 && dest != 68 {
			continue
		}
		boot := udp[8:ulen]
		if len(boot) < 240 || boot[0] != 2 || !bytes.Equal(boot[236:240], []byte{99, 130, 83, 99}) {
			continue
		}
		opts := map[byte][]byte{}
		valid := true
		for i := 240; i < len(boot); {
			code := boot[i]
			i++
			if code == 255 {
				break
			}
			if code == 0 {
				continue
			}
			if i >= len(boot) {
				valid = false
				break
			}
			n := int(boot[i])
			i++
			if n > len(boot)-i {
				valid = false
				break
			}
			if _, exists := opts[code]; exists {
				valid = false
				break
			}
			opts[code] = boot[i : i+n]
			i += n
		}
		if !valid || len(opts[53]) != 1 || (opts[53][0] != 2 && opts[53][0] != 5 && opts[53][0] != 6) {
			continue
		}
		source := net.IP(ip[12:16]).String()
		server := ""
		if len(opts[54]) == 4 {
			v := net.IP(opts[54])
			if v.IsGlobalUnicast() {
				server = v.String()
			}
		}
		if server == "" {
			server = source
		}
		network := ""
		if len(opts[1]) == 4 {
			mask := net.IPMask(opts[1])
			ones, bits := mask.Size()
			addr := net.IP(boot[16:20])
			if bits == 32 && ones > 0 && !addr.IsUnspecified() {
				network = (&net.IPNet{IP: addr.Mask(mask), Mask: mask}).String()
			}
		}
		relay := !net.IP(boot[24:28]).IsUnspecified() || server != source
		key := server + "|" + source + "|" + mac + "|" + network
		if found[key] == nil {
			if len(found) >= 100 {
				continue
			}
			found[key] = &DHCPServer{IP: server, Source: source, MAC: mac, Network: network, Relay: relay}
		}
		found[key].Responses++
	}
	out := make([]DHCPServer, 0, len(found))
	for _, s := range found {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP+out[i].MAC < out[j].IP+out[j].MAC })
	return out, nil
}
func dhcpVendor(mac string) string {
	addr, err := net.ParseMAC(mac)
	if err != nil || len(addr) != 6 {
		return "Não identificado"
	}
	if addr[0]&2 != 0 {
		return "MAC administrado localmente; fabricante indeterminado"
	}
	f, err := os.Open("/usr/share/nmap/nmap-mac-prefixes")
	if err != nil {
		return "Base OUI local indisponível"
	}
	defer f.Close()
	prefix := strings.ToUpper(strings.ReplaceAll(mac, ":", ""))[:6]
	scanner := bufio.NewScanner(io.LimitReader(f, 8<<20))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, prefix+" ") {
			v := strings.TrimSpace(line[7:])
			if len(v) > 120 {
				v = v[:120]
			}
			return redact(v)
		}
	}
	return "Não identificado na base OUI local"
}
func dhcpJobSnapshot(j *dhcpJob) map[string]any {
	j.mu.Lock()
	defer j.mu.Unlock()
	return map[string]any{"id": j.id, "status": j.status, "message": j.message, "servers": j.servers, "diagnosis": j.diagnosis}
}
func dhcpRemoteInterfaces(ctx context.Context, t *sshTerminal) ([]string, error) {
	select {
	case sshProbeSlots <- struct{}{}:
		defer func() { <-sshProbeSlots }()
	default:
		return nil, errors.New("há verificações SSH em andamento; tente novamente")
	}
	t.mu.Lock()
	client := t.client
	connected := t.status == "connected"
	t.mu.Unlock()
	if !connected || client == nil {
		return nil, errors.New("terminal desconectado")
	}
	stopOpen := context.AfterFunc(ctx, func() { client.Close() })
	s, err := client.NewSession()
	stopOpen()
	if err != nil {
		return nil, err
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	b := &limitedCapture{limit: 8192, cancel: func() { client.Close() }}
	s.Stdout = b
	s.Stderr = io.Discard
	if s.Run("/sbin/ifconfig -l") != nil {
		return nil, errors.New("não foi possível listar interfaces; confira a permissão SSH")
	}
	out := []string{}
	for _, name := range strings.Fields(string(b.copy())) {
		if dhcpInterface.MatchString(name) && !strings.HasPrefix(name, "lo") {
			out = append(out, name)
		}
	}
	return out, nil
}
func (a *App) runDHCP(ctx context.Context, j *dhcpJob, t *sshTerminal, command string) {
	defer func() { <-dhcpSlots; j.cancel() }()
	finish := func(status, message string) { j.mu.Lock(); j.status = status; j.message = message; j.mu.Unlock() }
	t.mu.Lock()
	client := t.client
	connected := t.status == "connected"
	t.mu.Unlock()
	if client == nil || !connected {
		finish("failed", "Terminal desconectado.")
		return
	}
	stopOpen := context.AfterFunc(ctx, func() { client.Close() })
	s, err := client.NewSession()
	stopOpen()
	if err != nil {
		finish("failed", "Não foi possível abrir a captura SSH.")
		return
	}
	defer s.Close()
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	b := &limitedCapture{limit: 2 << 20, cancel: j.cancel}
	s.Stdout = b
	s.Stderr = io.Discard
	if err = s.Start(command); err != nil {
		finish("failed", "O equipamento recusou a captura.")
		return
	}
	// Capture has its own remote watchdog; the request context adds a hard local bound.
	captureErr := s.Wait()
	if ctx.Err() != nil {
		finish("cancelled", "Consulta interrompida ou limite atingido.")
		return
	}
	if captureErr != nil {
		finish("failed", "Captura interrompida ou recusada; confira a interface e a permissão tcpdump.")
		return
	}
	servers, err := parseDHCPCapture(b.copy())
	if err != nil {
		finish("failed", err.Error())
		return
	}
	for i := range servers {
		servers[i].Vendor = dhcpVendor(servers[i].MAC)
	}
	j.mu.Lock()
	j.servers = servers
	j.status = "analyzing"
	j.message = "Captura concluída; preparando interpretação local."
	j.mu.Unlock()
	if len(servers) == 0 {
		finish("completed", "Nenhuma resposta DHCP observada nesta janela. Isso não comprova ausência de servidores.")
		return
	}
	a.mu.Lock()
	model := a.localAISnapshot().Model
	ready := a.aiStatus.Ready
	a.mu.Unlock()
	if ready {
		facts := dhcpModelFacts(servers)
		result, e := generateLocalDiagnosisContext(ctx, Event{Kind: "pfsense", Message: "Consulta passiva DHCP. Não classifique nenhum servidor como autorizado ou invasor. MAC pode ser de relay. Fabricante OUI não identifica modelo. Dados observados: " + string(facts)}, model)
		if e == nil && ctx.Err() == nil {
			j.mu.Lock()
			j.diagnosis = &result
			j.mu.Unlock()
		} else if ctx.Err() == nil {
			finish("completed", "Dados coletados; interpretação da IA indisponível. Nenhuma classificação automática.")
			return
		}
	}

	if ctx.Err() != nil {
		finish("cancelled", "Consulta interrompida; confira os dados já coletados.")
		return
	}
	finish("completed", "Respostas DHCP observadas. Você decide quais servidores são autorizados; OUI é apenas uma indicação.")
}
func (a *App) registerDHCPRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/ssh/sessions/{id}/dhcp/interfaces", a.auth(func(w http.ResponseWriter, r *http.Request) {
		t, ok := a.getSSHTerminal(r)
		if !ok || t.equipment.Kind != "pfsense" {
			http.NotFound(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		out, err := dhcpRemoteInterfaces(ctx, t)
		if err != nil {
			http.Error(w, err.Error(), 502)
			return
		}
		writeJSON(w, map[string]any{"interfaces": out})
	}))
	mux.HandleFunc("POST /api/ssh/sessions/{id}/dhcp", a.auth(func(w http.ResponseWriter, r *http.Request) {
		if a.demo || !a.nativeTLS {
			http.Error(w, "consulta requer HTTPS instalado", 503)
			return
		}
		t, ok := a.getSSHTerminal(r)
		if !ok || t.equipment.Kind != "pfsense" {
			http.NotFound(w, r)
			return
		}
		var body struct {
			Interface string `json:"interface"`
			Seconds   int    `json:"seconds"`
		}
		if !decode(w, r, &body) {
			return
		}
		command, err := dhcpCaptureCommand(body.Interface, body.Seconds)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		select {
		case dhcpSlots <- struct{}{}:
		default:
			http.Error(w, "duas consultas em andamento; aguarde", 429)
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(body.Seconds+105)*time.Second)
		j := &dhcpJob{id: token(), terminalID: t.id, owner: t.owner, equipment: t.equipment, status: "capturing", started: time.Now(), cancel: cancel, servers: []DHCPServer{}}
		dhcpJobs.Lock()
		for id, old := range dhcpJobs.jobs {
			old.mu.Lock()
			active := old.status == "capturing" || old.status == "analyzing"
			expired := time.Since(old.started) > 10*time.Minute
			old.mu.Unlock()
			if !active && expired {
				delete(dhcpJobs.jobs, id)
			}
			if active && old.terminalID == t.id {
				dhcpJobs.Unlock()
				cancel()
				<-dhcpSlots
				http.Error(w, "uma consulta já está ativa neste equipamento", 409)
				return
			}
		}
		if len(dhcpJobs.jobs) >= 32 {
			dhcpJobs.Unlock()
			cancel()
			<-dhcpSlots
			http.Error(w, "limite de consultas recentes; tente mais tarde", 429)
			return
		}
		dhcpJobs.jobs[j.id] = j
		dhcpJobs.Unlock()
		go a.runDHCP(ctx, j, t, command)
		writeJSON(w, dhcpJobSnapshot(j))
	}))
	get := func(r *http.Request) *dhcpJob {
		current, ok := a.session(r)
		if !ok {
			return nil
		}
		dhcpJobs.Lock()
		j := dhcpJobs.jobs[r.PathValue("job")]
		dhcpJobs.Unlock()
		if j == nil || j.owner != strings.ToLower(current.Email) {
			return nil
		}
		t, ok := a.getSSHTerminal(r)
		if !ok || j.terminalID != t.id {
			return nil
		}
		t.mu.Lock()
		t.lastRead = time.Now()
		t.mu.Unlock()
		return j
	}
	mux.HandleFunc("GET /api/ssh/sessions/{id}/dhcp/{job}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		j := get(r)
		if j == nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, dhcpJobSnapshot(j))
	}))
	mux.HandleFunc("POST /api/ssh/sessions/{id}/dhcp/{job}/cancel", a.auth(func(w http.ResponseWriter, r *http.Request) {
		j := get(r)
		if j == nil {
			http.NotFound(w, r)
			return
		}
		j.cancel()
		writeJSON(w, map[string]bool{"ok": true})
	}))
}

// Bound context before JSON encoding, preserving complete structured facts for the model.
func dhcpModelFacts(servers []DHCPServer) []byte {
	sample := servers
	if len(sample) > 4 {
		sample = sample[:4]
	}
	sample = append([]DHCPServer(nil), sample...)
	for i := range sample {
		if len(sample[i].Vendor) > 40 {
			sample[i].Vendor = sample[i].Vendor[:40]
		}
	}
	facts, _ := json.Marshal(map[string]any{"observed_servers": len(servers), "partial_sample": len(servers) > len(sample), "sample": sample})
	return facts
}
