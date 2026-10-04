package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

func makeCertificate(host string) ([]byte, []byte, string, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, "", e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return nil, nil, "", e
	}
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: host, Organization: []string{"Multipla Siem"}}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if ip := net.ParseIP(host); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	} else {
		cert.DNSNames = []string{host}
	}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if e != nil {
		return nil, nil, "", e
	}
	private, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return nil, nil, "", e
	}
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), hex.EncodeToString(sum[:]), nil
}
func setupHost(s string) bool {
	if _, e := netip.ParseAddr(s); e == nil {
		return true
	}
	if len(s) > 253 || !strings.Contains(s, ".") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, ch := range label {
			if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' {
				return false
			}
		}
	}
	return true
}
func prompt(r *bufio.Reader, label, fallback string) (string, error) {
	fmt.Printf("%s", label)
	if fallback != "" {
		fmt.Printf(" [%s]", fallback)
	}
	fmt.Print(": ")
	s, e := r.ReadString('\n')
	if e != nil {
		return "", errors.New("entrada encerrada; configuração cancelada")
	}
	s = strings.TrimSpace(s)
	if s == "" {
		s = fallback
	}
	return s, nil
}
func runSetup() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("execute a configuração em Linux como root: sudo multipla-setup")
	}
	r := bufio.NewReader(os.Stdin)
	fmt.Print("\033[2J\033[H\033[38;5;85m\n  MULTIPLA SIEM\n  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m\n  Instalação local · Configuração segura · Sem nuvem obrigatória\n\n")
	fmt.Println("[1/5] Identidade e acesso administrativo")
	path := "/var/lib/multipla-siem/config.json"
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return errors.New("execute scripts/install.sh antes da configuração")
	}
	if e = jsonUnmarshalConfig(b, &c); e != nil {
		return e
	}
	hostDefault := ""
	if u, e := url.Parse(c.PublicURL); e == nil && u.Hostname() != "siem.example.com" {
		hostDefault = u.Hostname()
	}
	host, e := prompt(r, "Nome DNS do servidor ou IP (Google SSO requer domínio aceito pelo Google)", hostDefault)
	if e != nil {
		return e
	}
	if !setupHost(host) {
		return errors.New("informe domínio DNS válido ou endereço IP")
	}
	emailDefault := ""
	if len(c.AllowedEmails) > 0 && c.AllowedEmails[0] != "admin@gmail.com" {
		emailDefault = c.AllowedEmails[0]
	}
	email, e := prompt(r, "Email do administrador", emailDefault)
	if e != nil {
		return e
	}
	c.AllowedEmails = []string{email}
	c.MailTo = email
	c.PublicURL = "https://" + net.JoinHostPort(host, "8443")
	c.Listen = "0.0.0.0:8443"
	c.DataDir = "/var/lib/multipla-siem"
	c.TLSCert = "/etc/multipla-siem/tls.crt"
	c.TLSKey = "/etc/multipla-siem/tls.key"
	c.AutoBlock = false
	fmt.Println("\n[2/5] Dispositivos · deixe vazio para configurar depois no painel")
	existing := map[string]string{}
	for _, d := range c.Devices {
		existing[d.Kind] = d.IP
	}
	var devices []Device
	for _, kind := range []string{"pfsense", "proxmox"} {
		fallback := existing[kind]
		if fallback == "192.168.1.1" || fallback == "192.168.1.10" {
			fallback = ""
		}
		ipText, e := prompt(r, "IP de origem "+kind, fallback)
		if e != nil {
			return e
		}
		if ipText == "" {
			continue
		}
		ip, e := netip.ParseAddr(ipText)
		if e != nil {
			return errors.New("IP de dispositivo inválido")
		}
		devices = append(devices, Device{kind, ip.Unmap().String(), kind})
	}
	c.Devices = devices
	if e = validateConfig(c); e != nil {
		return e
	}
	fmt.Println("\n[3/5] HTTPS · certificado exclusivo desta instalação")
	serviceUser, e := user.Lookup("multipla-siem")
	if e != nil {
		return errors.New("usuário do serviço não encontrado")
	}
	uid, _ := strconv.Atoi(serviceUser.Uid)
	gid, _ := strconv.Atoi(serviceUser.Gid)
	var fingerprint string
	reuse := false
	if certPEM, e := os.ReadFile(c.TLSCert); e == nil {
		if block, _ := pem.Decode(certPEM); block != nil {
			if cert, e := x509.ParseCertificate(block.Bytes); e == nil && cert.VerifyHostname(host) == nil && time.Now().Before(cert.NotAfter) {
				sum := sha256.Sum256(block.Bytes)
				fingerprint = hex.EncodeToString(sum[:])
				reuse = true
			}
		}
	}
	if !reuse {
		cert, key, fp, e := makeCertificate(host)
		if e != nil {
			return e
		}
		if e = os.WriteFile(c.TLSKey, key, 0600); e != nil {
			return e
		}
		if e = os.Chown(c.TLSKey, 0, gid); e != nil {
			return e
		}
		if e = os.Chmod(c.TLSKey, 0640); e != nil {
			return e
		}
		if e = os.WriteFile(c.TLSCert, cert, 0644); e != nil {
			return e
		}
		fingerprint = fp
	}
	fmt.Println("Certificado gerado/reutilizado. Confirme esta impressão digital por este console:")
	fmt.Println("SHA256:", fingerprint)
	fmt.Println("Instale a confiança nos clientes ou substitua por certificado de sua CA. Não ignore um certificado diferente deste.")
	fmt.Println("\n[4/5] Salvar configuração e iniciar serviço")
	if e = atomicJSON(path, c); e != nil {
		return e
	}
	if e = os.Chown(path, uid, gid); e != nil {
		return e
	}
	if e = rotateBootstrapFile(credentialsPath()); e != nil {
		return e
	}
	// Protect a manual configuration from the automatic pre-start helper.
	if e = os.WriteFile("/etc/multipla-siem/configured", []byte("manual-setup\n"), 0600); e != nil {
		return e
	}
	cmd := exec.Command("systemctl", "restart", "multipla-siem.service")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if e = cmd.Run(); e != nil {
		return errors.New("falha ao iniciar; consulte journalctl -u multipla-siem")
	}
	fmt.Println("\nPainel:", c.PublicURL)
	fmt.Println("O token inicial foi renovado. É de uso único, disponível por 15 minutos; seu uso permanece registrado após reiniciar. Leia-o como root em /etc/multipla-siem/secrets.env.")
	fmt.Println("Configure Google/Gmail após instalar. Não há contas ou senhas compartilhadas dentro da ISO.")
	fmt.Println("\n[5/5] Atualizações opcionais")
	conn, err := net.DialTimeout("tcp", "deb.debian.org:443", 3*time.Second)
	if err != nil {
		fmt.Println("Sem conectividade detectada. Instalação offline concluída; atualize posteriormente.")
	} else {
		conn.Close()
		answer, e := prompt(r, "Há conectividade. Buscar e aplicar atualizações Debian agora? (s/N)", "n")
		if e != nil {
			return e
		}
		if strings.EqualFold(answer, "s") {
			if e := setupUpdateSources(); e != nil {
				return e
			}
			for _, args := range [][]string{{"update"}, {"upgrade"}} {
				cmd := exec.Command("apt-get", args...)
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr
				if e = cmd.Run(); e != nil {
					return errors.New("atualização falhou; aplicação e dados foram preservados")
				}
			}
		} else {
			fmt.Println("Atualizações não executadas.")
		}
	}
	if e := os.WriteFile("/etc/multipla-siem/configured", []byte(time.Now().UTC().Format(time.RFC3339)), 0600); e != nil {
		return e
	}
	fmt.Println("\nMULTIPLA SIEM · Configuração concluída. Respostas automáticas permanecem em simulação até você ativar a publicação.")
	return nil
}
func jsonUnmarshalConfig(b []byte, c *Config) error { return json.Unmarshal(b, c) }

// Keep private credentials outside the service-writable data directory.
func credentialsPath() string { return filepath.Join("/etc", "multipla-siem", "secrets.env") }

func rotateBootstrapFile(path string) error {
	values, e := readCredentialValues(path)
	if e != nil {
		return e
	}
	values["BOOTSTRAP_TOKEN"] = token()
	var b strings.Builder
	for _, name := range secretNames {
		fmt.Fprintf(&b, "%s=%s\n", name, values[name])
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".credentials-*")
	if e != nil {
		return e
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if e = f.Chmod(0600); e == nil {
		_, e = f.WriteString(b.String())
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

func setupUpdateSources() error {
	b, e := os.ReadFile("/etc/os-release")
	if e != nil {
		return e
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = strings.Trim(v, "\"")
		}
	}
	if values["ID"] != "debian" {
		return nil
	}
	codename := values["VERSION_CODENAME"]
	if codename != "trixie" && codename != "bookworm" {
		return errors.New("atualize os repositórios da sua versão Debian manualmente")
	}
	data := "Types: deb\nURIs: https://deb.debian.org/debian\nSuites: " + codename + " " + codename + "-updates\nComponents: main non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n\nTypes: deb\nURIs: https://security.debian.org/debian-security\nSuites: " + codename + "-security\nComponents: main non-free-firmware\nSigned-By: /usr/share/keyrings/debian-archive-keyring.gpg\n"
	if e = os.WriteFile("/etc/apt/sources.list.d/multipla-official.sources", []byte(data), 0644); e != nil {
		return e
	}
	if old, e := os.ReadFile("/etc/apt/sources.list"); e == nil {
		var lines []string
		for _, line := range strings.Split(string(old), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "deb cdrom:") {
				line = "# " + line
			}
			lines = append(lines, line)
		}
		if e = os.WriteFile("/etc/apt/sources.list", []byte(strings.Join(lines, "\n")), 0644); e != nil {
			return e
		}
	}
	return nil
}
