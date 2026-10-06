package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func installFullBackupSchedule(email string) error {
	if _, err := fullDriveAccess(email); err != nil {
		return err
	}
	if _, err := recoveryKey(recoveryKeyPath, true); err != nil {
		return err
	}
	data, err := os.ReadFile("/var/lib/multipla-siem/state.json")
	if err != nil {
		return err
	}
	var state State
	if err = json.Unmarshal(data, &state); err != nil {
		return err
	}
	p := defaultPreferences()
	if stored, ok := state.Preferences[strings.ToLower(email)]; ok {
		p = stored
	}
	if err = validatePreferences(p); err != nil {
		return err
	}
	unit := "[Unit]\nDescription=Multipla Siem - backup completo criptografado\nAfter=network-online.target tailscaled.service\nWants=network-online.target\n\n[Service]\nType=oneshot\nTimeoutStartSec=0\nUMask=0077\nExecStart=/usr/local/bin/multipla-siem -full-backup -backup-drive " + strconv.Quote(strings.ReplaceAll(email, "%", "%%")) + "\n"
	timer := "[Unit]\nDescription=Multipla Siem - backup completo diario\n\n[Timer]\nOnCalendar=*-*-* " + p.BackupTime + ":00 " + p.BackupTimezone + "\nPersistent=true\nRandomizedDelaySec=60\nUnit=multipla-full-backup.service\n\n[Install]\nWantedBy=timers.target\n"
	if err = os.WriteFile("/etc/systemd/system/multipla-full-backup.service", []byte(unit), 0644); err != nil {
		return err
	}
	if err = os.WriteFile("/etc/systemd/system/multipla-full-backup.timer", []byte(timer), 0644); err != nil {
		return err
	}
	if err = runFullCommand("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err = runFullCommand("systemctl", "enable", "--now", "multipla-full-backup.timer"); err != nil {
		return err
	}
	fmt.Println("Backup completo diario ativado:", p.BackupTime, p.BackupTimezone, "— guarde a chave de recuperacao fora do servidor:", recoveryKeyPath)
	return nil
}
