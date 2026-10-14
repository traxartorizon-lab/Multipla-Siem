package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const sshCAPath = "/etc/multipla-siem/ssh-ca.key"
const sshCAPolicyPath = "/etc/multipla-siem/ssh-ca-policy.json"
const sshRequestPath = "/var/lib/multipla-siem/ssh-sign-request.json"
const sshResponsePath = "/var/lib/multipla-siem/ssh-sign-response.json"

var sshSignMu sync.Mutex
var delegatedSSHAuth = delegatedSSHMethod

type sshCAPolicy struct {
	Targets []string `json:"targets"`
	Sources []string `json:"sources"`
}
type sshSignRequest struct {
	ID        string    `json:"id"`
	Owner     string    `json:"owner"`
	Target    string    `json:"target"`
	PublicKey string    `json:"public_key"`
	Time      time.Time `json:"time"`
}
type sshSignResponse struct {
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
}

func signSSHRequest(req sshSignRequest, policy sshCAPolicy, ca ssh.Signer, now time.Time) (*ssh.Certificate, error) {
	ip, err := netip.ParseAddr(req.Target)
	allowed := false
	for _, target := range policy.Targets {
		if target == req.Target {
			allowed = true
		}
	}
	if err != nil || ip.String() != req.Target || !allowed || len(req.ID) != 43 || req.Owner == "" || len(req.Owner) > 254 || strings.ContainsAny(req.Owner, "\r\n\x00") || now.Sub(req.Time) > 30*time.Second || req.Time.After(now.Add(5*time.Second)) {
		return nil, errors.New("solicitação SSH fora da política root")
	}
	public, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
	if err != nil || public.Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("chave pública efêmera Ed25519 obrigatória")
	}
	sources := []string{}
	for _, source := range policy.Sources {
		addr, err := netip.ParseAddr(source)
		if err != nil {
			return nil, errors.New("origem SSH inválida")
		}
		bits := 128
		if addr.Is4() {
			bits = 32
		}
		sources = append(sources, fmt.Sprintf("%s/%d", addr, bits))
	}
	if len(sources) == 0 {
		return nil, errors.New("configure origem do SIEM na política root")
	}
	cert := &ssh.Certificate{Key: public, CertType: ssh.UserCert, KeyId: req.ID + ":" + req.Owner, ValidPrincipals: []string{"multipla-ops@" + req.Target}, ValidAfter: uint64(now.Add(-5 * time.Second).Unix()), ValidBefore: uint64(now.Add(5 * time.Minute).Unix()), Permissions: ssh.Permissions{CriticalOptions: map[string]string{"source-address": strings.Join(sources, ",")}, Extensions: map[string]string{"permit-pty": ""}}}
	if err = cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return cert, nil
}
func runSSHSigner() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("assinador SSH exige unidade root")
	}
	raw, err := os.ReadFile(sshCAPolicyPath)
	if err != nil {
		return err
	}
	var policy sshCAPolicy
	if err = json.Unmarshal(raw, &policy); err != nil {
		return err
	}
	if err = regularFile(sshRequestPath); err != nil {
		return err
	}
	info, err := os.Stat(sshRequestPath)
	if err != nil || info.Size() > 16384 {
		return errors.New("solicitação SSH inválida")
	}
	raw, err = os.ReadFile(sshRequestPath)
	if err != nil {
		return err
	}
	var req sshSignRequest
	if err = json.Unmarshal(raw, &req); err != nil {
		return err
	}
	raw, err = os.ReadFile(filepath.Join(os.Getenv("CREDENTIALS_DIRECTORY"), "ssh-ca.key"))
	if err != nil {
		return err
	}
	ca, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return err
	}
	cert, err := signSSHRequest(req, policy, ca, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("SSH_CERT_ISSUED owner=%q target=%q id=%q expires=%d\n", req.Owner, req.Target, req.ID, cert.ValidBefore)
	if err = atomicJSON(sshResponsePath, sshSignResponse{ID: req.ID, Certificate: string(ssh.MarshalAuthorizedKey(cert))}); err != nil {
		return err
	}
	// Public certificate only; the private ephemeral key remains in the service's memory.
	return os.Chmod(sshResponsePath, 0644)
}
func delegatedSSHMethod(ctx context.Context, d NetworkEquipment, owner string) (ssh.AuthMethod, error) {
	if d.SSHUser != "multipla-ops" {
		return nil, errors.New("configure a conta SSH exclusiva multipla-ops; root, admin e chaves pessoais não são aceitos")
	}
	sshSignMu.Lock()
	defer sshSignMu.Unlock()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		return nil, err
	}
	request := sshSignRequest{ID: token(), Owner: owner, Target: d.IP, PublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey())), Time: time.Now().UTC()}
	if err = atomicJSON(sshRequestPath, request); err != nil {
		return nil, errors.New("fila de assinatura SSH indisponível")
	}
	defer os.Remove(sshRequestPath)
	runCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if exec.CommandContext(runCtx, "systemctl", "start", "multipla-ssh-sign.service").Run() != nil {
		return nil, errors.New("assinatura SSH não habilitada; consulte o runbook de delegação")
	}
	raw, err := os.ReadFile(sshResponsePath)
	if err != nil {
		return nil, errors.New("certificado SSH indisponível")
	}
	var response sshSignResponse
	if json.Unmarshal(raw, &response) != nil || response.ID != request.ID {
		return nil, errors.New("resposta SSH não corresponde à solicitação")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(response.Certificate))
	if err != nil {
		return nil, err
	}
	cert, ok := key.(*ssh.Certificate)
	if !ok || !equal(string(cert.Key.Marshal()), string(signer.PublicKey().Marshal())) {
		return nil, errors.New("certificado inválido")
	}
	trusted, err := os.ReadFile("/etc/multipla-siem/ssh-ca.pub")
	if err != nil {
		return nil, err
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey(trusted)
	if err != nil || !equal(string(ca.Marshal()), string(cert.SignatureKey.Marshal())) {
		return nil, errors.New("CA SSH não corresponde à raiz instalada")
	}
	checker := ssh.CertChecker{SupportedCriticalOptions: []string{"source-address"}}
	if err = checker.CheckCert("multipla-ops@"+d.IP, cert); err != nil {
		return nil, err
	}
	certificateSigner, err := ssh.NewCertSigner(cert, signer)
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeys(certificateSigner), nil
}
