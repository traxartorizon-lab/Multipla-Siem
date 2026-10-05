package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const recoveryKeyPath = "/root/multipla-siem-recovery.key"
const fullBackupDirectory = "/var/backups/multipla-siem/full"

var fullRoots = []string{"etc/multipla-siem", "var/lib/multipla-siem", "var/lib/tailscale/tailscaled.state", "usr/local/bin/multipla-siem", "usr/local/lib/multipla-siem/updater", "usr/local/sbin/multipla-update", "etc/systemd/system/multipla-siem.service", "etc/systemd/system/multipla-firstboot.service", "etc/systemd/system/multipla-full-backup.service", "etc/systemd/system/multipla-full-backup.timer"}

type FullRecoveryManifest struct {
	Product      string `json:"product"`
	Schema       int    `json:"schema"`
	TimerEnabled bool   `json:"timer_enabled"`
}

func permittedFullPath(name string) bool {
	if name == "multipla-recovery.json" {
		return true
	}
	if name == "" || strings.ContainsAny(name, "\\\x00") || path.IsAbs(name) || path.Clean(name) != name {
		return false
	}
	for _, root := range fullRoots {
		if name == root || ((root == "etc/multipla-siem" || root == "var/lib/multipla-siem") && strings.HasPrefix(name, root+"/")) {
			return true
		}
	}
	return false
}

func recoveryKey(file string, create bool) ([]byte, error) {
	info, err := os.Lstat(file)
	if os.IsNotExist(err) && create {
		key := make([]byte, 32)
		if _, err = io.ReadFull(rand.Reader, key); err != nil {
			return nil, err
		}
		f, e := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return nil, e
		}
		_, err = f.WriteString(hex.EncodeToString(key) + "\n")
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return key, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 128 || (runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("chave de recuperacao ausente ou sem permissao 600")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 32 {
		return nil, errors.New("chave de recuperacao invalida")
	}
	return key, nil
}

func pauseFullServices(includeTailscale bool) (func() error, error) {
	var active []string
	restart := func() error {
		var result error
		for i := len(active) - 1; i >= 0; i-- {
			if err := runFullCommand("systemctl", "start", active[i]); err != nil {
				result = err
			}
		}
		return result
	}
	for _, service := range []string{"multipla-siem", "tailscaled"} {
		if service == "tailscaled" && !includeTailscale {
			continue
		}
		if exec.Command("systemctl", "is-active", "--quiet", service).Run() == nil {
			active = append(active, service)
			if err := runFullCommand("systemctl", "stop", service); err != nil {
				restart()
				return nil, err
			}
		}
	}
	return restart, nil
}

func runFullCommand(name string, args ...string) error {
	c := exec.Command(name, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func archiveFull(w io.Writer) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	metadata, _ := json.Marshal(FullRecoveryManifest{Product: "Multipla Siem", Schema: 1, TimerEnabled: exec.Command("systemctl", "is-enabled", "--quiet", "multipla-full-backup.timer").Run() == nil})
	if err := tw.WriteHeader(&tar.Header{Name: "multipla-recovery.json", Mode: 0600, Size: int64(len(metadata)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(metadata); err != nil {
		return err
	}
	var total int64
	count := 0
	for _, root := range fullRoots {
		if _, err := os.Lstat("/" + root); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		err := filepath.Walk("/"+root, func(file string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			name := strings.TrimPrefix(filepath.ToSlash(file), "/")
			if name == "var/lib/multipla-siem/backups" {
				return filepath.SkipDir
			}
			if !info.Mode().IsRegular() && !info.IsDir() {
				return fmt.Errorf("arquivo especial ou link recusado: %s", name)
			}
			if info.IsDir() {
				return nil
			}
			f, err := os.Open(file)
			if err != nil {
				return err
			}
			defer f.Close()
			info, err = f.Stat()
			if err != nil || !info.Mode().IsRegular() {
				return errors.New("arquivo de backup mudou")
			}
			total += info.Size()
			count++
			if total > fullBackupLimit || count > 100000 {
				return errors.New("backup excede limite de arquivos ou 64 GiB")
			}
			h, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			h.Name = name
			if err = tw.WriteHeader(h); err != nil {
				return err
			}
			_, err = io.CopyN(tw, f, info.Size())
			f.Close()
			return err
		})
		if err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	return gz.Close()
}

func createFullFile(key []byte) (string, error) {
	if err := os.MkdirAll(fullBackupDirectory, 0700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(fullBackupDirectory, ".creating-")
	if err != nil {
		return "", err
	}
	temp := f.Name()
	defer os.Remove(temp)
	r, w := io.Pipe()
	done := make(chan error, 1)
	go func() { err := archiveFull(w); w.CloseWithError(err); done <- err }()
	err = encryptFull(f, r, key)
	r.CloseWithError(err)
	archiveErr := <-done
	if err == nil {
		err = archiveErr
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return "", err
	}
	name := filepath.Join(fullBackupDirectory, "multipla-full-"+time.Now().UTC().Format("20060102T150405.000000000Z")+".msbk")
	if err = os.Rename(temp, name); err != nil {
		return "", err
	}
	return name, nil
}

func extractFull(r io.Reader, dir string) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer gz.Close()
	// Bound the entire expanded stream, including TAR padding and trailing data.
	expanded := &io.LimitedReader{R: gz, N: fullBackupLimit + (128 << 20)}
	tw := tar.NewReader(expanded)
	seen := map[string]bool{}
	var total int64
	for count := 0; ; count++ {
		h, err := tw.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if count >= 100000 || h.Typeflag != tar.TypeReg || h.Size < 0 || !permittedFullPath(h.Name) || seen[h.Name] {
			return errors.New("conteudo do backup recusado")
		}
		if (h.Name == "multipla-recovery.json" && h.Size > 8192) || ((h.Name == "var/lib/multipla-siem/config.json" || h.Name == "var/lib/multipla-siem/state.json") && h.Size > 16<<20) || (h.Name == "etc/multipla-siem/secrets.env" && h.Size > 65536) {
			return errors.New("arquivo de configuracao excede limite")
		}
		seen[h.Name] = true
		total += h.Size
		if total > fullBackupLimit {
			return errors.New("conteudo excede 64 GiB")
		}
		file := filepath.Join(dir, filepath.FromSlash(h.Name))
		if err = os.MkdirAll(filepath.Dir(file), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(file, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = io.CopyN(f, tw, h.Size)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	if _, err = io.Copy(io.Discard, expanded); err != nil {
		return err
	}
	if expanded.N == 0 {
		return errors.New("arquivo expandido excede limite")
	}
	for _, name := range []string{"multipla-recovery.json", "etc/multipla-siem/secrets.env", "var/lib/multipla-siem/config.json", "var/lib/multipla-siem/state.json", "usr/local/bin/multipla-siem", "usr/local/lib/multipla-siem/updater"} {
		if !seen[name] {
			return fmt.Errorf("backup incompleto: %s", name)
		}
	}
	rawMeta, err := os.ReadFile(filepath.Join(dir, "multipla-recovery.json"))
	if err != nil {
		return err
	}
	var meta FullRecoveryManifest
	if json.Unmarshal(rawMeta, &meta) != nil || meta.Product != "Multipla Siem" || meta.Schema != 1 {
		return errors.New("manifesto de recuperacao invalido")
	}
	if meta.TimerEnabled && (!seen["etc/systemd/system/multipla-full-backup.service"] || !seen["etc/systemd/system/multipla-full-backup.timer"]) {
		return errors.New("agendamento recuperado incompleto")
	}
	var cfg Config
	data, err := os.ReadFile(filepath.Join(dir, "var/lib/multipla-siem/config.json"))
	if err != nil {
		return err
	}
	if json.Unmarshal(data, &cfg) != nil || validateConfig(cfg) != nil || cfg.DataDir != "/var/lib/multipla-siem" {
		return errors.New("configuracao recuperada invalida")
	}
	for _, cert := range []string{cfg.TLSCert, cfg.TLSKey} {
		if !strings.HasPrefix(cert, "/etc/multipla-siem/") || !seen[strings.TrimPrefix(cert, "/")] {
			return errors.New("certificado ausente ou caminho nao suportado")
		}
	}
	var state State
	if _, err := tls.LoadX509KeyPair(filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(cfg.TLSCert, "/"))), filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(cfg.TLSKey, "/")))); err != nil {
		return errors.New("certificado e chave recuperados invalidos")
	}
	data, err = os.ReadFile(filepath.Join(dir, "var/lib/multipla-siem/state.json"))
	if err != nil || json.Unmarshal(data, &state) != nil {
		return errors.New("estado recuperado invalido")
	}
	return nil
}

func installFullStage(stage string) error {
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
	return filepath.Walk(stage, func(source string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(stage, source)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(rel)
		if name == "multipla-recovery.json" {
			return nil
		}
		if info.IsDir() {
			if name == "etc/multipla-siem" || strings.HasPrefix(name, "etc/multipla-siem/") {
				target := "/" + name
				if err := safeFullParents(target); err != nil {
					return err
				}
				if existing, e := os.Lstat(target); e == nil && !existing.IsDir() {
					return errors.New("diretorio de credenciais invalido")
				}
				if err := os.MkdirAll(target, 0750); err != nil {
					return err
				}
				if err := os.Chown(target, 0, gid); err != nil {
					return err
				}
				if err := os.Chmod(target, 0750); err != nil {
					return err
				}
			}
			if name == "var/lib/multipla-siem" || strings.HasPrefix(name, "var/lib/multipla-siem/") {
				target := "/" + name
				if err := safeFullParents(target); err != nil {
					return err
				}
				if existing, e := os.Lstat(target); e == nil && !existing.IsDir() {
					return errors.New("diretorio de dados invalido")
				}
				if err := os.MkdirAll(target, 0700); err != nil {
					return err
				}
				if err := os.Chown(target, uid, gid); err != nil {
					return err
				}
			}
			return nil
		}
		if !permittedFullPath(name) {
			return errors.New("caminho de restauracao recusado")
		}
		target := "/" + name
		if err = safeFullParents(target); err != nil {
			return err
		}
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return err
		}
		// Existing parents must not redirect a privileged restore through symlinks.
		for parent := filepath.Dir(target); parent != "/"; parent = filepath.Dir(parent) {
			i, e := os.Lstat(parent)
			if e != nil || !i.IsDir() {
				return errors.New("diretorio de restauracao invalido")
			}
		}
		f, err := os.CreateTemp(filepath.Dir(target), ".full-restore-")
		if err != nil {
			return err
		}
		temp := f.Name()
		defer os.Remove(temp)
		in, err := os.Open(source)
		if err != nil {
			f.Close()
			return err
		}
		_, err = io.Copy(f, in)
		in.Close()
		if err == nil {
			err = f.Sync()
		}
		f.Close()
		if err != nil {
			return err
		}
		mode := os.FileMode(0600)
		owner, group := 0, 0
		if strings.HasPrefix(name, "var/lib/multipla-siem/") {
			owner, group = uid, gid
		}
		if strings.HasPrefix(name, "etc/multipla-siem/") {
			mode = 0640
			group = gid
		}
		if strings.HasPrefix(name, "usr/local/") {
			mode = 0755
		}
		if err = os.Chmod(temp, mode); err != nil {
			return err
		}
		if err = os.Chown(temp, owner, group); err != nil {
			return err
		}
		return os.Rename(temp, target)
	})
}

func safeFullParents(target string) error {
	for parent := filepath.Dir(target); parent != "/"; parent = filepath.Dir(parent) {
		info, err := os.Lstat(parent)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() {
			return errors.New("diretorio de restauracao invalido ou link simbolico")
		}
	}
	return nil
}

func runFullBackup(restore, driveEmail, keyFile string, replaceServer bool) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("backup completo exige root no Debian/Ubuntu")
	}
	if keyFile == "" {
		keyFile = recoveryKeyPath
	}
	key, err := recoveryKey(keyFile, restore == "")
	if err != nil {
		return err
	}
	if restore != "" {
		if !replaceServer {
			return errors.New("restauracao total exige -replace-server: desligue o servidor original para nao duplicar sua identidade Tailscale")
		}
		if err := os.MkdirAll("/var/backups/multipla-siem", 0700); err != nil {
			return err
		}
		stage, err := os.MkdirTemp("/var/backups/multipla-siem", ".restore-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(stage)
		file, err := os.Open(restore)
		if err != nil {
			return err
		}
		defer file.Close()
		r, w := io.Pipe()
		done := make(chan error, 1)
		go func() { err := decryptFull(w, file, key); w.CloseWithError(err); done <- err }()
		err = extractFull(r, stage)
		if err == nil {
			_, err = io.Copy(io.Discard, r)
		}
		r.CloseWithError(err)
		cryptErr := <-done
		if err != nil {
			return err
		}
		if cryptErr != nil {
			return cryptErr
		}
		restart, err := pauseFullServices(true)
		if err != nil {
			return err
		}
		defer restart()
		checkpoint, err := createFullFile(key)
		if err != nil {
			return err
		}
		fmt.Println("Checkpoint antes da restauracao:", checkpoint)
		if err = installFullStage(stage); err != nil {
			return fmt.Errorf("restauracao interrompida: %w; checkpoint %s", err, checkpoint)
		}
		if err = installRecoveryKey(key); err != nil {
			return err
		}
		if err = runFullCommand("systemctl", "daemon-reload"); err != nil {
			return err
		}
		check := exec.Command("/usr/local/bin/multipla-siem", "-check", "-config", "/var/lib/multipla-siem/config.json")
		check.Env = append(os.Environ(), "CREDENTIALS_DIRECTORY=/etc/multipla-siem")
		if err = check.Run(); err != nil {
			return fmt.Errorf("verificacao da restauracao falhou; checkpoint %s", checkpoint)
		}
		if err = restart(); err != nil {
			return fmt.Errorf("restauracao copiada, reinicio falhou; checkpoint %s", checkpoint)
		}
		metadata, err := os.ReadFile(filepath.Join(stage, "multipla-recovery.json"))
		if err != nil {
			return err
		}
		var manifest FullRecoveryManifest
		if json.Unmarshal(metadata, &manifest) != nil || manifest.Product != "Multipla Siem" || manifest.Schema != 1 {
			return errors.New("manifesto de recuperacao invalido")
		}
		if manifest.TimerEnabled {
			if err = runFullCommand("systemctl", "enable", "--now", "multipla-full-backup.timer"); err != nil {
				return err
			}
		}
		fmt.Println("Backup completo restaurado. Certificados e autorizacoes continuam sujeitos a expiracao ou revogacao.")
		return nil
	}
	restart, err := pauseFullServices(false)
	if err != nil {
		return err
	}
	file, err := createFullFile(key)
	restartErr := restart()
	if err != nil {
		return err
	}
	if restartErr != nil {
		return restartErr
	}
	fmt.Println("Backup completo criptografado:", file, "\nChave separada:", keyFile, "— guarde uma copia fora do servidor; ela nao e enviada ao Drive.")
	if driveEmail != "" {
		if err = uploadFullDrive(driveEmail, file); err != nil {
			return fmt.Errorf("backup local concluido, envio Drive falhou: %w", err)
		}
		fmt.Println("Backup completo enviado ao Drive.")
	}
	return nil
}

func installRecoveryKey(key []byte) error {
	f, err := os.CreateTemp("/root", ".multipla-key-")
	if err != nil {
		return err
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.WriteString(hex.EncodeToString(key) + "\n"); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(temp, recoveryKeyPath)
}
