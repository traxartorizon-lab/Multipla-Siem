package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type NetworkEquipment struct {
	SSHUser string `json:"ssh_user,omitempty"`
	SSHPort int    `json:"ssh_port,omitempty"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	IP      string `json:"ip"`
	Kind    string `json:"kind"`
	Client  string `json:"client"`
	Unit    string `json:"unit"`
}
type NetworkTest struct {
	ID        string           `json:"id"`
	Equipment NetworkEquipment `json:"equipment"`
	Mode      string           `json:"mode"`
	Ports     string           `json:"ports,omitempty"`
	Status    string           `json:"status"`
	Started   time.Time        `json:"started"`
	Finished  time.Time        `json:"finished,omitempty"`
	Output    []string         `json:"output"`
	cancel    context.CancelFunc
}

func validateEquipment(d NetworkEquipment) error {
	for _, s := range []string{d.Name, d.Client, d.Unit} {
		if len(strings.TrimSpace(s)) == 0 || len(s) > 120 {
			return errors.New("informe nome, cliente e unidade (até 120 caracteres)")
		}
	}
	if d.Kind != "switch" && d.Kind != "router" && d.Kind != "firewall" && d.Kind != "access-point" && d.Kind != "server" && d.Kind != "pfsense" && d.Kind != "proxmox" {
		return errors.New("tipo de equipamento inválido")
	}
	if d.SSHPort < 0 || d.SSHPort > 65535 || (d.SSHUser != "" && !regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.@-]{0,63}$`).MatchString(d.SSHUser)) {
		return errors.New("usuário ou porta SSH inválidos")
	}
	ip, err := netip.ParseAddr(d.IP)
	if err != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Zone() != "" {
		return errors.New("informe um IP unicast de gerenciamento válido, sem nome DNS")
	}
	return nil
}
func networkCommand(mode, ip string) (string, []string, time.Duration, error) {
	if addr, err := netip.ParseAddr(ip); err != nil || !addr.IsGlobalUnicast() || addr.IsLoopback() || addr.Zone() != "" {
		return "", nil, 0, errors.New("destino inválido")
	}
	if runtime.GOOS != "linux" {
		return "", nil, 0, errors.New("testes disponíveis no servidor Linux")
	}
	switch mode {
	case "quick":
		return "ping", []string{"-n", "-c", "4", "-W", "2", "-w", "12", "--", ip}, 15 * time.Second, nil
	case "continuous":
		return "ping", []string{"-n", "-i", "1", "--", ip}, 30 * time.Minute, nil
	case "trace":
		return "traceroute", []string{"-n", "-m", "20", "-q", "1", "-w", "1", "--", ip}, 30 * time.Second, nil
	}
	return "", nil, 0, errors.New("teste inválido")
}
func (a *App) registerNetworkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/network", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		jobs := []NetworkTest{}
		for _, job := range a.networkTests {
			copy := *job
			copy.Output = append([]string{}, job.Output...)
			jobs = append(jobs, copy)
		}
		writeJSON(w, map[string]any{"devices": a.state.NetworkEquipment, "tests": jobs})
	}))
	mux.HandleFunc("PUT /api/network/equipment", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var d NetworkEquipment
		if !decode(w, r, &d) {
			return
		}
		d.Name = strings.TrimSpace(d.Name)
		d.Client = strings.TrimSpace(d.Client)
		d.Unit = strings.TrimSpace(d.Unit)
		d.IP = strings.TrimSpace(d.IP)
		if err := validateEquipment(d); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		ip, _ := netip.ParseAddr(d.IP)
		d.IP = ip.Unmap().String()
		a.mu.Lock()
		defer a.mu.Unlock()
		old := append([]NetworkEquipment{}, a.state.NetworkEquipment...)
		found := -1
		for i, current := range old {
			if current.ID == d.ID && d.ID != "" {
				found = i
			}
			if current.Client == d.Client && current.Unit == d.Unit && current.IP == d.IP && current.ID != d.ID {
				http.Error(w, "IP já cadastrado nesta unidade", 409)
				return
			}
		}
		if d.ID != "" && found < 0 {
			http.NotFound(w, r)
			return
		}
		if found < 0 {
			if len(old) >= 500 {
				http.Error(w, "limite de 500 equipamentos", 409)
				return
			}
			d.ID = token()
			a.state.NetworkEquipment = append(a.state.NetworkEquipment, d)
		} else {
			a.state.NetworkEquipment[found] = d
		}
		if err := a.persist(); err != nil {
			a.state.NetworkEquipment = old
			http.Error(w, "falha ao salvar equipamento", 500)
			return
		}
		writeJSON(w, d)
	}))
	mux.HandleFunc("DELETE /api/network/equipment/{id}", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		id := r.PathValue("id")
		old := append([]NetworkEquipment{}, a.state.NetworkEquipment...)
		found := false
		next := []NetworkEquipment{}
		for _, d := range old {
			if d.ID == id {
				found = true
			} else {
				next = append(next, d)
			}
		}
		if !found {
			http.NotFound(w, r)
			return
		}
		a.state.NetworkEquipment = next
		oldHost, hostExists := a.state.SSHHostKeys[id]
		delete(a.state.SSHHostKeys, id)
		if err := a.persist(); err != nil {
			a.state.NetworkEquipment = old
			if hostExists {
				a.state.SSHHostKeys[id] = oldHost
			}
			http.Error(w, "falha ao remover equipamento", 500)
			return
		}
		for _, terminal := range a.sshTerminals {
			if terminal.equipment.ID == id {
				terminal.close("Cadastro removido")
			}
		}
		for _, job := range a.networkTests {
			if job.Equipment.ID == id && job.Status == "running" {
				job.cancel()
				job.Status = "stopped"
			}
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("POST /api/network/tests", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IDs   []string `json:"ids"`
			Mode  string   `json:"mode"`
			Ports string   `json:"ports"`
		}
		if !decode(w, r, &body) {
			return
		}
		if len(body.IDs) < 1 || len(body.IDs) > 8 {
			http.Error(w, "selecione de um a oito equipamentos", 400)
			return
		}
		a.mu.Lock()
		selected := []NetworkEquipment{}
		seen := map[string]bool{}
		for _, id := range body.IDs {
			if seen[id] {
				a.mu.Unlock()
				http.Error(w, "equipamento repetido", 400)
				return
			}
			seen[id] = true
			found := false
			for _, d := range a.state.NetworkEquipment {
				if d.ID == id {
					selected = append(selected, d)
					found = true
					break
				}
			}
			if !found {
				a.mu.Unlock()
				http.Error(w, "selecione somente equipamentos cadastrados", 400)
				return
			}
		}
		running := 0
		for _, job := range a.networkTests {
			if job.Status == "running" {
				running++
			}
		}
		if running+len(selected) > 8 {
			a.mu.Unlock()
			http.Error(w, "há testes em execução; interrompa-os antes de iniciar outros", 429)
			return
		}
		if body.Mode == "ports" {
			if err := validateScanPorts(body.Ports); err != nil {
				a.mu.Unlock()
				http.Error(w, err.Error(), 400)
				return
			}
		}
		if body.Mode != "quick" && body.Mode != "continuous" && body.Mode != "trace" && body.Mode != "ports" {
			a.mu.Unlock()
			http.Error(w, "teste inválido", 400)
			return
		}
		if a.networkTests == nil {
			a.networkTests = map[string]*NetworkTest{}
		}
		// Retain a bounded result window; running tests are never evicted.
		for len(a.networkTests)+len(selected) > 32 {
			var oldest *NetworkTest
			for _, job := range a.networkTests {
				if job.Status != "running" && (oldest == nil || job.Started.Before(oldest.Started)) {
					oldest = job
				}
			}
			if oldest == nil {
				break
			}
			delete(a.networkTests, oldest.ID)
		}
		ids := []string{}
		for _, d := range selected {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
			job := &NetworkTest{ID: token(), Equipment: d, Mode: body.Mode, Ports: body.Ports, Status: "running", Started: time.Now().UTC(), Output: []string{}, cancel: cancel}
			a.networkTests[job.ID] = job
			ids = append(ids, job.ID)
			go a.runNetworkTest(ctx, job)
		}
		a.mu.Unlock()
		writeJSON(w, map[string]any{"ids": ids})
	}))
	mux.HandleFunc("POST /api/network/tests/{id}/stop", a.auth(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		job := a.networkTests[r.PathValue("id")]
		if job == nil {
			http.NotFound(w, r)
			return
		}
		if job.Status == "running" {
			job.Status = "stopped"
			job.cancel()
		}
		writeJSON(w, map[string]bool{"ok": true})
	}))
}
func (a *App) runNetworkTest(parent context.Context, job *NetworkTest) {
	defer job.cancel()
	if a.demo {
		a.mu.Lock()
		job.Status = "simulated"
		job.Finished = time.Now().UTC()
		job.Output = []string{"Demonstração: nenhum pacote foi enviado. Execute o teste na instalação Linux."}
		a.mu.Unlock()
		return
	}
	name, args, timeout, err := networkCommand(job.Mode, job.Equipment.IP)
	if job.Mode == "ports" {
		name, args, timeout, err = portScanCommand(job.Equipment.IP, job.Ports)
	}
	if err != nil {
		a.finishNetworkTest(job, err)
		return
	}
	path, err := exec.LookPath(name)
	if err != nil {
		a.finishNetworkTest(job, fmt.Errorf("comando %s não instalado; consulte NETWORK-TOOLS.md", name))
		return
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	command := exec.CommandContext(ctx, path, args...)
	output, err := command.StdoutPipe()
	if err != nil {
		a.finishNetworkTest(job, err)
		return
	}
	command.Stderr = command.Stdout
	if err = command.Start(); err != nil {
		a.finishNetworkTest(job, err)
		return
	}
	reader := bufio.NewScanner(io.LimitReader(output, 4<<20))
	reader.Buffer(make([]byte, 4096), 65536)
	for reader.Scan() {
		line := redact(reader.Text())
		if len(line) > 1024 {
			line = line[:1024]
		}
		a.mu.Lock()
		job.Output = append(job.Output, line)
		limit := 200
		if job.Mode == "ports" {
			limit = 2000
		}
		if len(job.Output) > limit {
			job.Output = job.Output[len(job.Output)-limit:]
		}
		a.mu.Unlock()
	}
	if reader.Err() != nil {
		cancel()
	}
	err = command.Wait()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	a.finishNetworkTest(job, err)
}
func (a *App) finishNetworkTest(job *NetworkTest, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	job.Finished = time.Now().UTC()
	if job.Status == "stopped" {
		return
	}
	if err != nil {
		job.Status = "failed"
		job.Output = append(job.Output, err.Error())
		limit := 200
		if job.Mode == "ports" {
			limit = 2000
		}
		if len(job.Output) > limit {
			job.Output = job.Output[len(job.Output)-limit:]
		}
	} else {
		job.Status = "completed"
	}
}

func validateScanPorts(ports string) error {
	if ports == "" {
		return nil
	}
	if len(ports) > 2048 {
		return errors.New("lista de portas muito longa")
	}
	seen := map[int]bool{}
	for _, part := range strings.Split(ports, ",") {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return errors.New("use portas como 22,80,443 ou 1-1024")
		}
		first, err := strconv.Atoi(bounds[0])
		if err != nil || first < 1 || first > 65535 {
			return errors.New("porta inválida: permitido 1 a 65535")
		}
		last := first
		if len(bounds) == 2 {
			last, err = strconv.Atoi(bounds[1])
			if err != nil || last < first || last > 65535 {
				return errors.New("intervalo de portas inválido")
			}
		}
		if last-first >= 1024 {
			return errors.New("limite de 1024 portas por scan")
		}
		for port := first; port <= last; port++ {
			seen[port] = true
			if len(seen) > 1024 {
				return errors.New("limite de 1024 portas por scan")
			}
		}
	}
	return nil
}
func portScanCommand(ip, ports string) (string, []string, time.Duration, error) {
	if _, _, _, err := networkCommand("quick", ip); err != nil {
		return "", nil, 0, err
	}
	if err := validateScanPorts(ports); err != nil {
		return "", nil, 0, err
	}
	args := []string{"-sT", "-Pn", "-n", "--reason", "--max-retries", "1", "--host-timeout", "120s"}
	if strings.Contains(ip, ":") {
		args = append(args, "-6")
	}
	if ports == "" {
		args = append(args, "--top-ports", "100")
	} else {
		args = append(args, "-p", ports)
	}
	args = append(args, ip)
	return "nmap", args, 125 * time.Second, nil
}
