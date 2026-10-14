package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type assetDigest struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type assetsManifest struct {
	Product string                 `json:"product"`
	Version string                 `json:"version"`
	Schema  int                    `json:"schema"`
	Files   map[string]assetDigest `json:"files"`
}

func signAssets(args []string) error {
	if len(args) < 6 || len(args) > 520 {
		return fmt.Errorf("uso: sign-assets CHAVE VERSION MANIFESTO RAIZ ARQUIVO...")
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		return err
	}
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		return fmt.Errorf("chave privada inválida")
	}
	defer func() {
		for i := range private {
			private[i] = 0
		}
	}()
	manifest := assetsManifest{Product: "Multipla SIEM", Version: args[2], Schema: 1, Files: map[string]assetDigest{}}
	for _, name := range args[5:] {
		if name == "" || filepath.IsAbs(name) || strings.ContainsAny(name, "\\\x00") || filepath.ToSlash(filepath.Clean(name)) != name || strings.HasPrefix(name, "../") {
			return fmt.Errorf("caminho inválido")
		}
		path := filepath.Join(args[4], filepath.FromSlash(name))
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("artefato regular obrigatório: %s", name)
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		manifest.Files[name] = assetDigest{SHA256: hex.EncodeToString(sum[:]), Size: info.Size()}
	}
	raw, err = json.Marshal(manifest)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(args[3]), 0755); err != nil {
		return err
	}
	if err = os.WriteFile(args[3], raw, 0644); err != nil {
		return err
	}
	return os.WriteFile(strings.TrimSuffix(args[3], ".json")+".sig", ed25519.Sign(ed25519.PrivateKey(private), raw), 0644)
}
