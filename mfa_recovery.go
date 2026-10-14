package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Preflight is also run by the updater before switching the installed executable.
func checkMFAStorage(c Config) error {
	if _, err := driveCipher(); err != nil {
		return fmt.Errorf("MFA: %w", err)
	}
	path := filepath.Join(c.DataDir, "state.json")
	if err := regularFile(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var state State
	if err = json.Unmarshal(raw, &state); err != nil {
		return err
	}
	for email, record := range state.MFA {
		if _, err = openMFA(email, record.EncryptedSecret); err != nil {
			return errors.New("MFA: chave de criptografia não abre uma credencial existente; preserve a chave original")
		}
	}
	return nil
}

func resetMFARecord(state *State, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if _, ok := state.MFA[email]; !ok {
		return errors.New("conta sem MFA cadastrado")
	}
	delete(state.MFA, email)
	for id, grant := range state.DesktopGrants {
		if strings.EqualFold(grant.Owner, email) {
			delete(state.DesktopGrants, id)
		}
	}
	state.Audit = append(state.Audit, Audit{Time: time.Now().UTC(), Actor: "root-console", Action: "recuperação MFA: " + email + "; vínculos Windows revogados"})
	if len(state.Audit) > 500 {
		state.Audit = state.Audit[len(state.Audit)-500:]
	}
	return nil
}

func recoverMFA(configPath, email string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("recuperação MFA exige root no console Linux")
	}
	if configPath != "/var/lib/multipla-siem/config.json" && configPath != "/etc/multipla-siem/config.json" {
		return errors.New("use a configuração instalada /var/lib/multipla-siem/config.json")
	}
	if exec.Command("systemctl", "is-active", "--quiet", "multipla-siem.service").Run() == nil {
		return errors.New("pare multipla-siem.service antes da recuperação para encerrar sessões e evitar escrita concorrente")
	}
	lock, err := os.OpenFile("/run/multipla-mfa-recovery.lock", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return errors.New("recuperação concorrente ou trava existente")
	}
	defer os.Remove(lock.Name())
	defer lock.Close()
	if err = regularFile(configPath); err != nil {
		return err
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	var cfg Config
	if err = json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	if cfg.DataDir != "/var/lib/multipla-siem" {
		return errors.New("recuperação exige o DataDir instalado /var/lib/multipla-siem")
	}
	path := filepath.Join(cfg.DataDir, "state.json")
	if err = regularFile(path); err != nil {
		return err
	}
	raw, err = os.ReadFile(path)
	if err != nil {
		return err
	}
	var state State
	if err = json.Unmarshal(raw, &state); err != nil {
		return err
	}
	if err = resetMFARecord(&state, email); err != nil {
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
	if err = atomicJSON(path, state); err != nil {
		return err
	}
	return os.Chown(path, uid, gid)
}
