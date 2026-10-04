package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
)

func automaticFirstBoot() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("primeiro boot exige Linux e root")
	}
	if _, err := os.Stat("/etc/multipla-siem/configured"); err == nil {
		return nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		return err
	}
	host := ""
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, addr := range addresses {
			ip, _, e := net.ParseCIDR(addr.String())
			if e == nil && ip.To4() != nil && !ip.IsLinkLocalUnicast() {
				host = ip.String()
				break
			}
		}
		if host != "" {
			break
		}
	}
	if host == "" {
		return errors.New("aguardando endereço IPv4; configure a rede no instalador Debian e reinicie")
	}
	path := "/var/lib/multipla-siem/config.json"
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var cfg Config
	if err = json.Unmarshal(data, &cfg); err != nil {
		return err
	}
	cfg.Listen = "0.0.0.0:8443"
	cfg.PublicURL = "https://" + net.JoinHostPort(host, "8443")
	cfg.TLSCert = "/etc/multipla-siem/tls.crt"
	cfg.TLSKey = "/etc/multipla-siem/tls.key"
	cfg.Devices = []Device{}
	cfg.AllowedEmails = []string{}
	cfg.MailTo = ""
	cfg.AutoBlock = false
	cfg.FirstBoot = true
	if err = validateConfig(cfg); err != nil {
		return err
	}
	cert, key, fingerprint, err := makeCertificate(host)
	if err != nil {
		return err
	}
	account, err := user.Lookup("multipla-siem")
	if err != nil {
		return err
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return err
	}
	if err = os.WriteFile(cfg.TLSKey, key, 0600); err != nil {
		return err
	}
	if err = os.Chown(cfg.TLSKey, 0, gid); err != nil {
		return err
	}
	if err = os.Chmod(cfg.TLSKey, 0640); err != nil {
		return err
	}
	if err = os.WriteFile(cfg.TLSCert, cert, 0644); err != nil {
		return err
	}
	if err = atomicJSON(path, cfg); err != nil {
		return err
	}
	if err = os.Chown(path, uid, gid); err != nil {
		return err
	}
	if err = rotateBootstrapFile(credentialsPath()); err != nil {
		return err
	}
	values, err := readCredentialValues(credentialsPath())
	if err != nil {
		return err
	}
	banner := fmt.Sprintf("\nMULTIPLA SIEM — Primeiro acesso\nPainel: %s\nCódigo exclusivo: %s\nCertificado SHA256: %s\nAbra o painel e cadastre sua conta administrativa.\n", cfg.PublicURL, values["BOOTSTRAP_TOKEN"], fingerprint)
	if err = os.WriteFile("/etc/issue", []byte(banner), 0600); err != nil {
		return err
	}
	return os.WriteFile("/etc/multipla-siem/configured", []byte("automatic-web-onboarding\n"), 0600)
}
