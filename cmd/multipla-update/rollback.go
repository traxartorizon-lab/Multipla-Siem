package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"time"
)

const updateBackupRoot = "/var/backups/multipla-siem"

var backupIDPattern = regexp.MustCompile(`^update-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z$`)
var snapshotNames = []string{"binary", "updater", "config.json", "state.json"}

func snapshotHashes(dir string) (map[string]string, error) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || (runtime.GOOS == "linux" && info.Mode().Perm()&0077 != 0) {
		return nil, errors.New("backup ausente ou sem permissao privada")
	}
	hashes := map[string]string{}
	for _, name := range snapshotNames {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > 64<<20 {
			return nil, fmt.Errorf("backup incompleto ou arquivo invalido: %s", name)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if filepath.Ext(name) == ".json" && !json.Valid(data) {
			return nil, fmt.Errorf("JSON de backup invalido: %s", name)
		}
		hash := sha256.Sum256(data)
		hashes[name] = hex.EncodeToString(hash[:])
	}
	return hashes, nil
}

func writeSnapshotManifest(dir string) error {
	hashes, err := snapshotHashes(dir)
	if err != nil {
		return err
	}
	data, err := json.Marshal(hashes)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "snapshot.json"), data, 0600)
}

func validateSnapshot(dir string) error {
	hashes, err := snapshotHashes(dir)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "snapshot.json")
	info, err := os.Lstat(path)
	// Versions 1.2.2/1.2.3 already created private snapshots without a manifest.
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4096 {
		return errors.New("manifesto local invalido")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var expected map[string]string
	if json.Unmarshal(data, &expected) != nil || len(expected) != len(hashes) {
		return errors.New("manifesto local invalido")
	}
	for name, digest := range hashes {
		if expected[name] != digest {
			return fmt.Errorf("integridade do backup falhou: %s", name)
		}
	}
	return nil
}

func updateBackups() ([]string, error) {
	entries, err := os.ReadDir(updateBackupRoot)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, entry := range entries {
		if backupIDPattern.MatchString(entry.Name()) && validateSnapshot(filepath.Join(updateBackupRoot, entry.Name())) == nil {
			ids = append(ids, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(ids)))
	return ids, nil
}

func listUpdateBackups() error {
	ids, err := updateBackups()
	if err != nil {
		return err
	}
	for _, id := range ids {
		fmt.Println(id)
	}
	if len(ids) == 0 {
		return errors.New("nenhum backup completo disponivel")
	}
	return nil
}

func replaceSnapshotFile(from, target string, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(target), ".multipla-restore-")
	if err != nil {
		return err
	}
	temp := f.Name()
	f.Close()
	defer os.Remove(temp)
	if err = command("cp", "-p", from, temp); err != nil {
		return err
	}
	if mode != 0 {
		if err = os.Chmod(temp, mode); err != nil {
			return err
		}
	}
	return os.Rename(temp, target)
}

func restoreApplicationSnapshot(dir string) error {
	if err := replaceSnapshotFile(filepath.Join(dir, "binary"), "/usr/local/bin/multipla-siem", 0755); err != nil {
		return err
	}
	for _, name := range []string{"config.json", "state.json"} {
		if err := replaceSnapshotFile(filepath.Join(dir, name), "/var/lib/multipla-siem/"+name, 0); err != nil {
			return err
		}
	}
	return nil
}

func rollbackUpdate(id string) error {
	if id == "" {
		ids, err := updateBackups()
		if err != nil || len(ids) == 0 {
			return errors.New("nenhum backup completo disponivel; use list-backups")
		}
		id = ids[0]
	}
	if !backupIDPattern.MatchString(id) {
		return errors.New("informe somente um ID mostrado por list-backups")
	}
	dir := filepath.Join(updateBackupRoot, id)
	if err := validateSnapshot(dir); err != nil {
		return err
	}
	if err := command("systemctl", "stop", "multipla-siem"); err != nil {
		return err
	}
	defer command("systemctl", "start", "multipla-siem")
	checkpoint := filepath.Join(updateBackupRoot, "before-rollback-"+time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.MkdirAll(checkpoint, 0700); err != nil {
		return err
	}
	for _, item := range []struct{ from, name string }{
		{"/usr/local/bin/multipla-siem", "binary"}, {"/usr/local/lib/multipla-siem/updater", "updater"},
		{"/var/lib/multipla-siem/config.json", "config.json"}, {"/var/lib/multipla-siem/state.json", "state.json"},
	} {
		if err := command("cp", "-p", item.from, filepath.Join(checkpoint, item.name)); err != nil {
			return err
		}
	}
	if err := writeSnapshotManifest(checkpoint); err != nil {
		return err
	}
	err := restoreApplicationSnapshot(dir)
	if err == nil {
		err = command("systemctl", "start", "multipla-siem")
	}
	if err == nil {
		err = waitHealthy()
	}
	if err != nil {
		if stopErr := command("systemctl", "stop", "multipla-siem"); stopErr != nil {
			return fmt.Errorf("rollback falhou; nao foi possivel parar: %v; checkpoint %s", stopErr, checkpoint)
		}
		if restoreErr := restoreApplicationSnapshot(checkpoint); restoreErr != nil {
			return fmt.Errorf("rollback falhou: %v; recuperacao falhou: %v; checkpoint %s", err, restoreErr, checkpoint)
		}
		return fmt.Errorf("rollback falhou: %v; estado anterior ao comando recuperado; checkpoint %s", err, checkpoint)
	}
	fmt.Println("Rollback concluido:", id, "— atualizador mantido; logs preservados. Alteracoes posteriores de configuracao foram revertidas. Checkpoint:", checkpoint)
	return nil
}
