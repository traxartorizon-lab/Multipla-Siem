package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const isolationPolicyPath = "/etc/multipla-siem/isolation-policy.json"
const isolationDiskPath = "/etc/multipla-siem/isolation-state.json"
const isolationRuntimePath = "/run/multipla-isolation/state.json"
const isolationReleasePath = "/var/lib/multipla-siem/isolation-release-request.json"

type isolationPolicy struct {
	Peers     []string `json:"peers"`
	Local     []string `json:"local"`
	Protected []string `json:"protected"`
}
type DirectIsolation struct {
	ID     string    `json:"id"`
	IP     string    `json:"ip"`
	Time   time.Time `json:"time"`
	Reason string    `json:"reason"`
}
type isolationRelease struct {
	ID    string    `json:"id"`
	IP    string    `json:"ip"`
	Actor string    `json:"actor"`
	Time  time.Time `json:"time"`
}
type directPacket struct {
	Source     string
	Port       int
	SourcePort int
	Time       time.Time
}

var directFields = regexp.MustCompile(`\b(SRC|DST|DPT|SPT|IN)=([^\s]+)`)

func trustedDirectPacket(raw []byte, policy isolationPolicy) (directPacket, bool) {
	var row map[string]string
	if json.Unmarshal(raw, &row) != nil || row["_TRANSPORT"] != "kernel" || !strings.HasPrefix(row["MESSAGE"], "MULTIPLA_DIRECT ") {
		return directPacket{}, false
	}
	fields := map[string]string{}
	for _, m := range directFields.FindAllStringSubmatch(row["MESSAGE"], -1) {
		fields[m[1]] = m[2]
	}
	if fields["IN"] != "tailscale0" {
		return directPacket{}, false
	}
	source, err := netip.ParseAddr(fields["SRC"])
	if err != nil {
		return directPacket{}, false
	}
	dest, err := netip.ParseAddr(fields["DST"])
	if err != nil {
		return directPacket{}, false
	}
	allowed, local := false, false
	for _, v := range policy.Peers {
		if v == source.String() {
			allowed = true
		}
	}
	for _, v := range policy.Local {
		if v == dest.String() {
			local = true
		}
	}
	for _, v := range policy.Protected {
		prefix, err := netip.ParsePrefix(v)
		if err == nil && prefix.Contains(source) {
			return directPacket{}, false
		}
	}
	if !allowed || !local || source == dest {
		return directPacket{}, false
	}
	port, err := strconv.Atoi(fields["DPT"])
	if err != nil || port < 1 || port > 65535 || port == 8443 || port == 5514 {
		return directPacket{}, false
	}
	sport, err := strconv.Atoi(fields["SPT"])
	if err != nil || sport < 1 || sport > 65535 {
		return directPacket{}, false
	}
	return directPacket{Source: source.String(), Port: port, SourcePort: sport, Time: time.Now().UTC()}, true
}
func nftInput(script string) error {
	cmd := exec.Command("/usr/sbin/nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	return cmd.Run()
}
func nftAddressSet(ips []string, v4 bool) string {
	out := []string{}
	for _, v := range ips {
		ip, err := netip.ParseAddr(v)
		if err == nil && ip.Is4() == v4 {
			out = append(out, ip.String())
		}
	}
	return strings.Join(out, ", ")
}
func isolationRules(policy isolationPolicy, blocks map[string]DirectIsolation) string {
	script := "table inet multipla_guard {\nset peers4 { type ipv4_addr; elements = { " + nftAddressSet(policy.Peers, true) + " }; }\nset peers6 { type ipv6_addr; elements = { " + nftAddressSet(policy.Peers, false) + " }; }\nset local4 { type ipv4_addr; elements = { " + nftAddressSet(policy.Local, true) + " }; }\nset local6 { type ipv6_addr; elements = { " + nftAddressSet(policy.Local, false) + " }; }\nset isolated4 { type ipv4_addr; }\nset isolated6 { type ipv6_addr; }\nchain input { type filter hook input priority -10; policy accept;\nip saddr @isolated4 drop\nip6 saddr @isolated6 drop\niifname \"tailscale0\" ip saddr @peers4 ip daddr @local4 tcp flags & (syn | ack) == syn tcp dport != { 8443, 5514 } limit rate 100/second burst 200 packets log prefix \"MULTIPLA_DIRECT \"\niifname \"tailscale0\" ip6 saddr @peers6 ip6 daddr @local6 tcp flags & (syn | ack) == syn tcp dport != { 8443, 5514 } limit rate 100/second burst 200 packets log prefix \"MULTIPLA_DIRECT \"\n}\n}\n"
	for _, b := range blocks {
		ip, err := netip.ParseAddr(b.IP)
		if err != nil {
			continue
		}
		set := "isolated6"
		if ip.Is4() {
			set = "isolated4"
		}
		script += "add element inet multipla_guard " + set + " { " + ip.String() + " }\n"
	}
	return script
}
func saveIsolationState(blocks map[string]DirectIsolation) error {
	if err := atomicJSON(isolationDiskPath, blocks); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(isolationRuntimePath), 0755); err != nil {
		return err
	}
	if err := atomicJSON(isolationRuntimePath, blocks); err != nil {
		return err
	}
	return os.Chmod(isolationRuntimePath, 0644)
}
func runIsolationAgent() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("isolamento exige agente root")
	}
	raw, err := os.ReadFile(isolationPolicyPath)
	if err != nil {
		return err
	}
	var policy isolationPolicy
	if json.Unmarshal(raw, &policy) != nil {
		return errors.New("política inválida")
	}
	blocks := map[string]DirectIsolation{}
	if raw, err := os.ReadFile(isolationDiskPath); err == nil {
		if json.Unmarshal(raw, &blocks) != nil {
			return errors.New("estado de isolamento inválido")
		}
	}
	// Replace only our named table in one transaction; errors keep the old rules.
	prefix := ""
	if exec.Command("/usr/sbin/nft", "list", "table", "inet", "multipla_guard").Run() == nil {
		prefix = "delete table inet multipla_guard\n"
	}
	if err = nftInput(prefix + isolationRules(policy, blocks)); err != nil {
		return err
	}
	if err = saveIsolationState(blocks); err != nil {
		return err
	}
	journal := exec.Command("/usr/bin/journalctl", "--follow", "--lines=0", "--output=json", "_TRANSPORT=kernel")
	stdout, err := journal.StdoutPipe()
	if err != nil {
		return err
	}
	if err = journal.Start(); err != nil {
		return err
	}
	defer journal.Process.Kill()
	packets := make(chan directPacket, 512)
	go func() {
		scan := bufio.NewScanner(stdout)
		scan.Buffer(make([]byte, 65536), 262144)
		for scan.Scan() {
			if packet, ok := trustedDirectPacket(scan.Bytes(), policy); ok {
				select {
				case packets <- packet:
				default:
					log.Print("ISOLATION_MONITOR_DROP: monitor saturado")
				}
			}
		}
		close(packets)
	}()
	recent := map[string][]directPacket{}
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case packet, ok := <-packets:
			if !ok {
				return errors.New("journalctl interrompido")
			}
			if _, exists := blocks[packet.Source]; exists {
				continue
			}
			window := []directPacket{}
			for _, v := range recent[packet.Source] {
				if packet.Time.Sub(v.Time) < time.Minute {
					window = append(window, v)
				}
			}
			if len(window) < 200 {
				window = append(window, packet)
			}
			recent[packet.Source] = window
			ports := map[int]bool{}
			sshAttempts := map[int]bool{}
			for _, v := range window {
				ports[v.Port] = true
				if v.Port == 22 {
					sshAttempts[v.SourcePort] = true
				}
			}
			if len(ports) < 10 && len(sshAttempts) < 20 {
				continue
			}
			if len(blocks) >= 256 {
				log.Print("ISOLATION_MONITOR_DROP: limite de dispositivos isolados")
				continue
			}
			ip, _ := netip.ParseAddr(packet.Source)
			set := "isolated6"
			if ip.Is4() {
				set = "isolated4"
			}
			b := DirectIsolation{ID: token(), IP: packet.Source, Time: packet.Time, Reason: "Ataques diretos ao SIEM: scan de portas ou tentativas repetidas na porta 22"}
			blocks[b.IP] = b
			if err = atomicJSON(isolationDiskPath, blocks); err != nil {
				delete(blocks, b.IP)
				log.Print("ISOLATION_PERSIST_FAILED: regra não aplicada")
				continue
			}
			if err = nftInput("add element inet multipla_guard " + set + " { " + ip.String() + " }\n"); err != nil {
				log.Print("ISOLATION_FAILED: nftables")
				delete(blocks, b.IP)
				atomicJSON(isolationDiskPath, blocks)
				continue
			}
			blocks[b.IP] = b
			if err = saveIsolationState(blocks); err != nil {
				log.Print("ISOLATION_PERSIST_FAILED")
			}
			log.Printf("ISOLATION_APPLIED ip=%q id=%q", b.IP, b.ID)
		case <-ticker.C:
			if regularFile(isolationReleasePath) != nil {
				continue
			}
			raw, err := os.ReadFile(isolationReleasePath)
			if err != nil || len(raw) > 4096 {
				continue
			}
			var request isolationRelease
			if json.Unmarshal(raw, &request) != nil {
				continue
			}
			b, ok := blocks[request.IP]
			if !ok || b.ID != request.ID || time.Since(request.Time) > 30*time.Second || request.Time.After(time.Now().Add(5*time.Second)) {
				os.Remove(isolationReleasePath)
				continue
			}
			ip, err := netip.ParseAddr(b.IP)
			if err != nil {
				continue
			}
			set := "isolated6"
			if ip.Is4() {
				set = "isolated4"
			}
			if nftInput("delete element inet multipla_guard "+set+" { "+ip.String()+" }\n") != nil {
				continue
			}
			delete(blocks, b.IP)
			delete(recent, b.IP)
			if err = saveIsolationState(blocks); err != nil {
				log.Print("ISOLATION_RELEASE_PERSIST_FAILED")
			}
			os.Remove(isolationReleasePath)
			log.Printf("ISOLATION_RELEASED ip=%q actor=%q id=%q", b.IP, request.Actor, b.ID)
		}
	}
}
func (a *App) acceptIsolationSnapshot(blocks map[string]DirectIsolation) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, b := range blocks {
		if a.state.IsolationSeen[b.IP] == b.ID {
			continue
		}
		var device Device
		found := false
		for _, candidate := range a.cfg.Devices {
			if candidate.IP == b.IP {
				device = candidate
				found = true
				break
			}
		}
		if !found {
			continue
		}
		e := Event{Tenant: device.Client, ID: b.ID, Time: b.Time, Device: device.Name, SenderIP: b.IP, SourceIP: b.IP, Kind: "local-security", Detector: "direct-siem-isolation", Message: b.Reason, Rule: "Dispositivo isolado no firewall do SIEM", Level: 15, Alert: true}
		if !a.appendEvent(e) {
			continue
		}
		if a.state.IsolationSeen == nil {
			a.state.IsolationSeen = map[string]string{}
		}
		old := a.state.IsolationSeen[b.IP]
		a.state.IsolationSeen[b.IP] = b.ID
		a.audit("root-isolation", b.Reason+"; "+b.IP)
		if a.persist() != nil {
			a.state.IsolationSeen[b.IP] = old
		}
	}
}
func (a *App) isolationWorker() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		raw, err := os.ReadFile(isolationRuntimePath)
		if err != nil || len(raw) > 262144 {
			continue
		}
		blocks := map[string]DirectIsolation{}
		if json.Unmarshal(raw, &blocks) != nil {
			continue
		}
		a.acceptIsolationSnapshot(blocks)
	}
}
func (a *App) registerIsolationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/isolation/release", a.auth(func(w http.ResponseWriter, r *http.Request) {
		s, _ := a.session(r)
		a.mu.Lock()
		allowed := a.groupLocked(s.Email) == groupSuperadmin
		a.mu.Unlock()
		if !allowed {
			http.Error(w, "Exige Superadmin", 403)
			return
		}
		var input struct {
			ID string `json:"id"`
			IP string `json:"ip"`
		}
		if !decode(w, r, &input) {
			return
		}
		raw, err := os.ReadFile(isolationRuntimePath)
		blocks := map[string]DirectIsolation{}
		if err != nil || json.Unmarshal(raw, &blocks) != nil {
			http.Error(w, "Agente de isolamento indisponível", 503)
			return
		}
		b, ok := blocks[input.IP]
		if !ok || b.ID != input.ID {
			http.NotFound(w, r)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.audit(s.Email, "liberação de isolamento solicitada: "+b.IP+"; "+b.ID)
		if a.persist() != nil {
			http.Error(w, "Auditoria indisponível", 503)
			return
		}
		if err = atomicJSON(isolationReleasePath, isolationRelease{ID: b.ID, IP: b.IP, Actor: s.Email, Time: time.Now().UTC()}); err != nil {
			http.Error(w, "Falha ao solicitar liberação", 503)
			return
		}
		writeJSON(w, map[string]any{"ok": true, "message": "Liberação solicitada ao agente root; confirme a comunicação após a remoção da regra."})
	}))
}
func enableIsolation(configPath string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("habilitação exige root")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		return errors.New("instale nftables pelo gerenciador do sistema")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg Config
	if json.Unmarshal(raw, &cfg) != nil {
		return errors.New("configuração inválida")
	}
	policy := isolationPolicy{Protected: cfg.Protected}
	interfaces, err := net.InterfaceAddrs()
	if err != nil {
		return err
	}
	for _, v := range interfaces {
		prefix, err := netip.ParsePrefix(v.String())
		if err == nil {
			policy.Local = append(policy.Local, prefix.Addr().String())
		}
	}
	for _, d := range cfg.Devices {
		policy.Peers = append(policy.Peers, d.IP)
	}
	if len(policy.Peers) > 256 || len(policy.Local) == 0 {
		return errors.New("política fora dos limites")
	}
	if err = atomicJSON(isolationPolicyPath, policy); err != nil {
		return err
	}
	unit := `[Unit]
Description=Multipla SIEM - isolamento de ataques diretos
After=tailscaled.service network-online.target
[Service]
User=root
ExecStart=/usr/local/bin/multipla-siem -isolation-agent
Restart=on-failure
RestartSec=5
RuntimeDirectory=multipla-isolation
RuntimeDirectoryMode=0755
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
PrivateTmp=true
ReadWritePaths=/etc/multipla-siem /var/lib/multipla-siem /run/multipla-isolation
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
MemoryMax=128M
TasksMax=16
[Install]
WantedBy=multi-user.target
`
	if err = os.WriteFile("/etc/systemd/system/multipla-isolation.service", []byte(unit), 0644); err != nil {
		return err
	}
	if err = exec.Command("/usr/bin/systemctl", "daemon-reload").Run(); err != nil {
		return err
	}
	return exec.Command("/usr/bin/systemctl", "enable", "--now", "multipla-isolation.service").Run()
}

func testIsolationRules() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("teste nftables exige root em namespace de rede isolado")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if current == host {
		return errors.New("execute via unshare --net; não testar no namespace do host")
	}
	script := isolationRules(isolationPolicy{Peers: []string{"100.64.0.10", "fd7a:115c:a1e0::10"}, Local: []string{"100.64.0.20", "fd7a:115c:a1e0::20"}}, map[string]DirectIsolation{})
	cmd := exec.Command("/usr/sbin/nft", "--check", "--file", "-")
	cmd.Stdin = strings.NewReader(script)
	cmd.Stderr = os.Stderr
	if err = cmd.Run(); err != nil {
		return fmt.Errorf("nftables rejeitou regras: %w", err)
	}
	return nil
}
