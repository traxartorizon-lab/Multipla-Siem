package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type settings struct {
	Repository string `json:"repository"`
	PublicKey  string `json:"public_key"`
}
type manifest struct {
	Version       string `json:"version"`
	Arch          string `json:"arch"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	UpdaterSHA256 string `json:"updater_sha256"`
	UpdaterSize   int64  `json:"updater_size"`
}

const updaterVersion = "1.2.12"

var versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)

func verify(raw, signature []byte, key ed25519.PublicKey, arch string) (manifest, error) {
	var m manifest
	if len(raw) > 4096 || len(signature) != ed25519.SignatureSize || !ed25519.Verify(key, raw, signature) {
		return m, errors.New("assinatura de release invalida")
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return m, err
	}
	digest, err := hex.DecodeString(m.SHA256)
	if err != nil || len(digest) != 32 || !versionPattern.MatchString(m.Version) || m.Arch != arch || m.Size < 1 || m.Size > 64<<20 {
		return m, errors.New("manifesto invalido")
	}
	updaterDigest, err := hex.DecodeString(m.UpdaterSHA256)
	if err != nil || len(updaterDigest) != 32 || m.UpdaterSize < 1 || m.UpdaterSize > 64<<20 {
		return m, errors.New("manifesto do atualizador invalido")
	}
	return m, nil
}
func permitted(u string) bool {
	return u == "github.com" || u == "release-assets.githubusercontent.com" || u == "objects.githubusercontent.com"
}
func download(url string, limit int64) ([]byte, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 120 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 5 || r.URL.Scheme != "https" || r.URL.User != nil || r.URL.Port() != "" || !permitted(r.URL.Hostname()) {
			return errors.New("redirecionamento recusado")
		}
		return nil
	}}
	response, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, fmt.Errorf("download HTTP %d", response.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, errors.New("download excedeu limite")
	}
	return b, nil
}
func command(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}
func copyFile(from, to string, mode os.FileMode) error {
	b, e := os.ReadFile(from)
	if e != nil {
		return e
	}
	return os.WriteFile(to, b, mode)
}
func healthy() error { return healthyContext(context.Background()) }

func healthyContext(ctx context.Context) error {
	raw, err := os.ReadFile("/var/lib/multipla-siem/config.json")
	if err != nil {
		return err
	}
	var cfg struct {
		PublicURL string `json:"public_url"`
		TLSCert   string `json:"tls_cert"`
	}
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	u, err := url.Parse(cfg.PublicURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return errors.New("URL HTTPS local invalida")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	pem, err := os.ReadFile(cfg.TLSCert)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return errors.New("certificado local invalido")
	}
	transport := &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", port))
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, "GET", cfg.PublicURL+"/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return fmt.Errorf("painel HTTP %d", response.StatusCode)
	}
	return nil
}
func update() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("execute como root no Debian/Ubuntu")
	}
	// Hold a kernel-managed advisory lock; it is released even after a crash.
	lock, err := os.OpenFile("/run/multipla-update.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	// flock wraps this process in the entry-point below; no stale PID lock.
	raw, err := os.ReadFile("/etc/multipla-siem/update.json")
	if err != nil {
		return errors.New("configure update.json com repository e public_key; consulte UPDATES.md")
	}
	var cfg settings
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil || len(key) != 32 || !repoPattern.MatchString(cfg.Repository) {
		return errors.New("origem/chave de atualizacao invalida")
	}
	base := "https://github.com/" + cfg.Repository + "/releases/"
	raw, err = download(base+"latest/download/manifest-"+runtime.GOARCH+".json", 4096)
	if err != nil {
		return err
	}
	sig, err := download(base+"latest/download/manifest-"+runtime.GOARCH+".sig", 64)
	if err != nil {
		return err
	}
	m, err := verify(raw, sig, ed25519.PublicKey(key), runtime.GOARCH)
	if err != nil {
		return err
	}
	current, err := exec.Command("/usr/local/bin/multipla-siem", "-version").Output()
	if err != nil {
		return err
	}
	fields := strings.Fields(string(current))
	if len(fields) == 0 {
		return errors.New("versao local invalida")
	}
	if exec.Command("dpkg", "--compare-versions", m.Version, "gt", fields[len(fields)-1]).Run() != nil {
		fmt.Println("Nenhuma versao mais recente.")
		return nil
	}
	binary, err := download(base+"download/v"+m.Version+"/multipla-siem-linux-"+runtime.GOARCH, m.Size)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(binary)
	if int64(len(binary)) != m.Size || hex.EncodeToString(hash[:]) != strings.ToLower(m.SHA256) {
		return errors.New("integridade do binario invalida")
	}
	updaterBinary, err := download(base+"download/v"+m.Version+"/multipla-update-linux-"+runtime.GOARCH, m.UpdaterSize)
	if err != nil {
		return err
	}
	updaterHash := sha256.Sum256(updaterBinary)
	if int64(len(updaterBinary)) != m.UpdaterSize || hex.EncodeToString(updaterHash[:]) != strings.ToLower(m.UpdaterSHA256) {
		return errors.New("integridade do atualizador invalida")
	}
	stage, err := os.MkdirTemp("/usr/local/bin", ".multipla-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	updaterStage, err := os.MkdirTemp("/usr/local/lib/multipla-siem", ".update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(updaterStage)
	nextUpdater := filepath.Join(updaterStage, "updater")
	if err = os.WriteFile(nextUpdater, updaterBinary, 0755); err != nil {
		return err
	}
	updaterReported, err := exec.Command(nextUpdater, "-version").Output()
	if err != nil || strings.TrimSpace(string(updaterReported)) != "Multipla Siem Updater "+m.Version {
		return errors.New("versao do atualizador nao corresponde ao manifesto")
	}
	next := filepath.Join(stage, "multipla-siem")
	if err = os.WriteFile(next, binary, 0755); err != nil {
		return err
	}
	reported, err := exec.Command(next, "-version").Output()
	if err != nil || strings.TrimSpace(string(reported)) != "Multipla Siem "+m.Version {
		return errors.New("versao do binario nao corresponde ao manifesto")
	}
	backup := filepath.Join("/var/backups/multipla-siem", "update-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err = os.MkdirAll(backup, 0700); err != nil {
		return err
	}
	if err = command("systemctl", "stop", "multipla-siem"); err != nil {
		return err
	}
	installed := false
	defer func() {
		if !installed {
			_ = command("systemctl", "start", "multipla-siem")
		}
	}()
	if err = copyFile("/usr/local/bin/multipla-siem", filepath.Join(backup, "binary"), 0700); err != nil {
		return err
	}
	if err = copyFile("/usr/local/lib/multipla-siem/updater", filepath.Join(backup, "updater"), 0700); err != nil {
		return err
	}
	for _, name := range []string{"config.json", "state.json"} {
		p := "/var/lib/multipla-siem/" + name
		if _, e := os.Stat(p); e == nil {
			if e = command("cp", "-p", p, filepath.Join(backup, name)); e != nil {
				return e
			}
		}
	}
	if err = writeSnapshotManifest(backup); err != nil {
		return err
	}
	helperChanged := false
	revert := func(cause error) error {
		if e := command("systemctl", "stop", "multipla-siem"); e != nil {
			return fmt.Errorf("%w; falha ao parar para retorno; backup %s", cause, backup)
		}
		if e := copyFile(filepath.Join(backup, "binary"), "/usr/local/bin/multipla-siem", 0755); e != nil {
			return fmt.Errorf("%w; retorno do executavel falhou: %v; backup %s", cause, e, backup)
		}
		if helperChanged {
			if e := copyFile(filepath.Join(backup, "updater"), "/usr/local/lib/multipla-siem/updater", 0755); e != nil {
				return fmt.Errorf("%w; retorno do atualizador falhou: %v; backup %s", cause, e, backup)
			}
		}
		for _, n := range []string{"config.json", "state.json"} {
			if _, e := os.Stat(filepath.Join(backup, n)); e == nil {
				if e = command("cp", "-p", filepath.Join(backup, n), "/var/lib/multipla-siem/"+n); e != nil {
					return fmt.Errorf("%w; retorno da configuracao falhou: %v; backup %s", cause, e, backup)
				}
			}
		}
		return fmt.Errorf("%w; versao anterior restaurada; backup %s", cause, backup)
	}

	if err = os.Rename(next, "/usr/local/bin/multipla-siem"); err != nil {
		return err
	}
	if err = os.Rename(nextUpdater, "/usr/local/lib/multipla-siem/updater"); err != nil {
		return revert(err)
	}
	helperChanged = true
	if err = command("systemctl", "start", "multipla-siem"); err != nil {
		return revert(errors.New("falha na partida"))
	}
	if err = exec.Command("systemctl", "is-active", "--quiet", "multipla-siem").Run(); err != nil {
		return revert(errors.New("servico falhou"))
	}
	if err = waitHealthy(); err != nil {
		return revert(fmt.Errorf("painel indisponivel: %w", err))
	}
	installed = true
	fmt.Println("Multipla Siem", m.Version, "instalada. Backup:", backup)
	return nil
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "-version" {
		fmt.Println("Multipla Siem Updater", updaterVersion)
		return
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "execute como root no Debian/Ubuntu")
		os.Exit(1)
	}
	args := os.Args[1:]
	if len(args) == 0 || args[0] != "--operation-locked" {
		executable, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cmd := exec.Command("flock", append([]string{"-n", "/run/multipla-updater-operation.lock", executable, "--operation-locked"}, args...)...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			os.Exit(1)
		}
		return
	}
	args = args[1:]
	var err error
	switch {
	case len(args) == 0:
		err = update()
	case len(args) == 1 && args[0] == "rollback":
		err = rollbackUpdate("")
	case len(args) == 2 && args[0] == "rollback":
		err = rollbackUpdate(args[1])
	case len(args) == 1 && args[0] == "list-backups":
		err = listUpdateBackups()
	default:
		err = errors.New("uso: multipla-update [rollback [update-ID] | list-backups]")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
