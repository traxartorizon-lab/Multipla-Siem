package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

var deviceQuerySlots = make(chan struct{}, 2)

func validateDeviceNetwork(d Device) error {
	if len(d.Client) > 120 || len(d.Unit) > 120 || strings.ContainsAny(d.Client+d.Unit, "\r\n\x00") {
		return errors.New("cliente ou unidade inválidos")
	}
	if d.MAC != "" {
		if _, err := magicPacket(d.MAC); err != nil {
			return err
		}
	}
	if d.WOLTarget != "" {
		ip, e := netip.ParseAddr(d.WOLTarget)
		if e != nil || !ip.Is4() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() || ip.String() == "255.255.255.255" {
			return errors.New("destino Wake-on-LAN deve ser IPv4 da rede do dispositivo; não use broadcast global")
		}
	}
	return nil
}
func magicPacket(value string) ([]byte, error) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || bytes.Equal(mac, make([]byte, 6)) {
		return nil, errors.New("MAC unicast inválido; use seis pares hexadecimais")
	}
	packet := bytes.Repeat([]byte{255}, 6)
	for i := 0; i < 16; i++ {
		packet = append(packet, mac...)
	}
	return packet, nil
}

// Fixed commands, no shell, no credential arguments, bounded stdout and stderr.
type limitedDeviceOutput struct{ b bytes.Buffer }

func (o *limitedDeviceOutput) Write(p []byte) (int, error) {
	n := len(p)
	if o.b.Len() < 32768 {
		left := 32768 - o.b.Len()
		if len(p) > left {
			p = p[:left]
		}
		o.b.Write(p)
	}
	return n, nil
}
func deviceCommand(ctx context.Context, path string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.WaitDelay = time.Second
	var out limitedDeviceOutput
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return redact(out.b.String()), err
}
func (a *App) registeredDevice(ip string) (Device, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, d := range a.cfg.Devices {
		if d.IP == ip {
			return d, true
		}
	}
	return Device{}, false
}
func (a *App) registerDeviceNetworkRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/devices/network", a.auth(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			IP     string `json:"ip"`
			Action string `json:"action"`
		}
		if !decode(w, r, &body) {
			return
		}
		d, ok := a.registeredDevice(body.IP)
		if !ok {
			http.NotFound(w, r)
			return
		}
		ip, e := netip.ParseAddr(d.IP)
		if e != nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.Zone() != "" {
			http.Error(w, "destino de cadastro inválido", 400)
			return
		}
		if a.demo {
			http.Error(w, "ação indisponível na demonstração", 403)
			return
		}
		if body.Action != "wake" && body.Action != "inspect" {
			http.Error(w, "ação inválida", 400)
			return
		}
		select {
		case deviceQuerySlots <- struct{}{}:
			defer func() { <-deviceQuerySlots }()
		default:
			http.Error(w, "duas consultas já estão em andamento", 429)
			return
		}
		current, _ := a.session(r)
		a.mu.Lock()
		a.audit(current.Email, "dispositivo: "+body.Action+" · "+d.Name+" · "+d.IP)
		err := a.persist()
		a.mu.Unlock()
		if err != nil {
			http.Error(w, "falha ao registrar auditoria", 500)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		if body.Action == "wake" {
			packet, err := magicPacket(d.MAC)
			if err != nil || d.WOLTarget == "" {
				http.Error(w, "configure MAC e destino Wake-on-LAN no cadastro", 400)
				return
			}
			if err = validateDeviceNetwork(d); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			conn, err := net.DialTimeout("udp4", net.JoinHostPort(d.WOLTarget, "9"), 2*time.Second)
			if err != nil {
				http.Error(w, "não foi possível alcançar o destino UDP", 502)
				return
			}
			defer conn.Close()
			if allowWOLBroadcast(conn) != nil {
				http.Error(w, "envio Wake-on-LAN indisponível neste servidor", 502)
				return
			}
			conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if _, err = conn.Write(packet); err != nil {
				http.Error(w, "falha ao enviar pacote Wake-on-LAN", 502)
				return
			}
			writeJSON(w, map[string]string{"result": "Pacote enviado. Isso não confirma que o PC ligou; verifique BIOS, placa de rede, energia e acesso à LAN."})
			return
		}
		names, err := net.DefaultResolver.LookupAddr(ctx, d.IP)
		host := "Não resolvido por DNS reverso"
		if err == nil && len(names) > 0 {
			host = strings.Join(names, ", ")
		}
		ports, pe := deviceCommand(ctx, "/usr/bin/nmap", "-sT", "-Pn", "-n", "--host-timeout", "15s", "--max-retries", "1", "-p", "22,80,135,139,443,445,3389,5985,5986", "--", d.IP)
		if pe != nil {
			ports = "Nmap indisponível ou consulta incompleta.\n" + ports
		}
		shares, se := deviceCommand(ctx, "/usr/bin/smbclient", "-L", d.IP, "-I", d.IP, "-U", "%", "-N", "-g", "-t", "5", "--option=client min protocol=SMB2", "--option=client max protocol=SMB3")
		if se != nil {
			shares = "Compartilhamentos não enumerados: SMB pode exigir autenticação, estar bloqueado ou smbclient não estar instalado.\n" + shares
		}
		neighbors, _ := deviceCommand(ctx, "/usr/sbin/ip", "neigh", "show", "to", d.IP)
		mac := d.MAC
		if mac == "" {
			mac = "Não cadastrado"
		}
		writeJSON(w, map[string]string{"hostname": host, "mac": mac, "neighbors": neighbors, "ports": ports, "shares": shares, "note": fmt.Sprintf("Consulta a partir do SIEM (%s). MAC observado só está disponível na mesma LAN; redes roteadas podem mostrar o próximo salto. As portas consultadas são uma seleção, não um scan completo.", d.IP)})
	}))
}
