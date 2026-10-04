package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Uso: release-sign keygen ARQUIVO_PRIVADO | sign CHAVE VERSION ARCH BINARIO PASTA")
		os.Exit(1)
	}
	if e := run(os.Args[1:]); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run(a []string) error {
	if a[0] == "keygen" && len(a) == 2 {
		pub, priv, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(a[1], os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write([]byte(base64.StdEncoding.EncodeToString(priv)))
		ce := f.Close()
		if e != nil {
			return e
		}
		if ce != nil {
			return ce
		}
		fmt.Println("Chave publica:", base64.StdEncoding.EncodeToString(pub))
		return nil
	}
	if a[0] != "sign" || len(a) != 6 {
		return fmt.Errorf("argumentos invalidos")
	}
	key, e := os.ReadFile(a[1])
	if e != nil {
		return e
	}
	priv, e := base64.StdEncoding.DecodeString(string(key))
	if e != nil || len(priv) != 64 {
		return fmt.Errorf("chave privada invalida")
	}
	b, e := os.ReadFile(a[4])
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	m := struct {
		Version string `json:"version"`
		Arch    string `json:"arch"`
		SHA256  string `json:"sha256"`
		Size    int    `json:"size"`
	}{a[2], a[3], hex.EncodeToString(h[:]), len(b)}
	raw, e := json.Marshal(m)
	if e != nil {
		return e
	}
	if e = os.MkdirAll(a[5], 0755); e != nil {
		return e
	}
	if e = os.WriteFile(filepath.Join(a[5], "manifest-"+a[3]+".json"), raw, 0644); e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(a[5], "manifest-"+a[3]+".sig"), ed25519.Sign(ed25519.PrivateKey(priv), raw), 0644)
}
