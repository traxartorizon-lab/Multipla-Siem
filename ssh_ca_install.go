package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"golang.org/x/crypto/ssh"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

const sshSignUnit = `[Unit]
Description=Multipla SIEM - assinatura restrita de certificado SSH
[Service]
Type=oneshot
User=root
LoadCredential=ssh-ca.key:/etc/multipla-siem/ssh-ca.key
ExecStart=/usr/local/bin/multipla-siem -ssh-sign
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_UNIX
ReadWritePaths=/var/lib/multipla-siem
TimeoutStartSec=10
UMask=0077
`
const sshSignPolicy = `polkit.addRule(function(action, subject) {
 if (action.id === "org.freedesktop.systemd1.manage-units" && subject.user === "multipla-siem" && action.lookup("unit") === "multipla-ssh-sign.service" && action.lookup("verb") === "start") return polkit.Result.YES;
});
`

func enableSSHCA(target, sources string) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("delegação SSH exige configuração pelo root")
	}
	ip, err := netip.ParseAddr(target)
	if err != nil || ip.String() != target {
		return errors.New("informe um IP exato de destino")
	}
	policy := sshCAPolicy{}
	if raw, err := os.ReadFile(sshCAPolicyPath); err == nil {
		if json.Unmarshal(raw, &policy) != nil {
			return errors.New("política SSH inválida")
		}
	}
	found := false
	for _, v := range policy.Targets {
		if v == target {
			found = true
		}
	}
	if !found {
		policy.Targets = append(policy.Targets, target)
	}
	if len(policy.Targets) > 256 {
		return errors.New("limite de destinos SSH")
	}
	if sources != "" {
		policy.Sources = nil
		for _, v := range strings.Split(sources, ",") {
			addr, err := netip.ParseAddr(strings.TrimSpace(v))
			if err != nil {
				return err
			}
			policy.Sources = append(policy.Sources, addr.String())
		}
	}
	if len(policy.Sources) == 0 || len(policy.Sources) > 8 {
		return errors.New("informe as origens do SIEM usando -ssh-source, separadas por vírgula")
	}
	if err = os.MkdirAll("/etc/multipla-siem", 0700); err != nil {
		return err
	}
	raw, err := os.ReadFile(sshCAPath)
	if os.IsNotExist(err) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		block, err := ssh.MarshalPrivateKey(private, "Multipla SIEM CA exclusiva")
		if err != nil {
			return err
		}
		raw = pem.EncodeToMemory(block)
		f, err := os.OpenFile(sshCAPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		_, err = f.Write(raw)
		if err == nil {
			err = f.Sync()
		}
		ce := f.Close()
		if err != nil {
			return err
		}
		if ce != nil {
			return ce
		}
	} else if err != nil {
		return err
	}
	if err = regularFile(sshCAPath); err != nil {
		return err
	}
	if err = os.Chmod(sshCAPath, 0600); err != nil {
		return err
	}
	if err = os.Chown(sshCAPath, 0, 0); err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		return err
	}
	if err = os.WriteFile("/etc/multipla-siem/ssh-ca.pub", ssh.MarshalAuthorizedKey(signer.PublicKey()), 0644); err != nil {
		return err
	}
	if err = atomicJSON(sshCAPolicyPath, policy); err != nil {
		return err
	}
	if err = os.WriteFile("/etc/systemd/system/multipla-ssh-sign.service", []byte(sshSignUnit), 0644); err != nil {
		return err
	}
	if err = os.WriteFile("/etc/polkit-1/rules.d/48-multipla-ssh-sign.rules", []byte(sshSignPolicy), 0644); err != nil {
		return err
	}
	return exec.Command("systemctl", "daemon-reload").Run()
}
