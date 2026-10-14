package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"time"
)

// Optional authenticated syslog transport for peers outside the existing private tunnel.
// The certificate must be issued for the registered source IP; names in the log are not identity.
func (a *App) syslogTLS() error {
	if a.cfg.SyslogTLS == "" {
		return nil
	}
	if a.cfg.SyslogClientCA == "" || a.cfg.TLSCert == "" || a.cfg.TLSKey == "" {
		return errors.New("syslog TLS exige certificado do servidor e CA de clientes")
	}
	raw, err := os.ReadFile(a.cfg.SyslogClientCA)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return errors.New("CA de clientes syslog inválida")
	}
	cert, err := tls.LoadX509KeyPair(a.cfg.TLSCert, a.cfg.TLSKey)
	if err != nil {
		return err
	}
	listener, err := tls.Listen("tcp", a.cfg.SyslogTLS, &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert})
	if err != nil {
		return err
	}
	slots := make(chan struct{}, 32)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			select {
			case slots <- struct{}{}:
			default:
				conn.Close()
				continue
			}
			go func(conn net.Conn) {
				defer conn.Close()
				defer func() { <-slots }()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				secure := conn.(*tls.Conn)
				if secure.Handshake() != nil {
					return
				}
				source, _, err := net.SplitHostPort(conn.RemoteAddr().String())
				if err != nil {
					return
				}
				device, ok := a.device(source)
				if !ok {
					return
				}
				state := secure.ConnectionState()
				if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].VerifyHostname(device.IP) != nil {
					return
				}
				conn.SetDeadline(time.Now().Add(2 * time.Minute))
				scanner := bufio.NewScanner(conn)
				scanner.Buffer(make([]byte, 4096), 16385)
				for scanner.Scan() {
					a.ingest(device, scanner.Text())
					conn.SetReadDeadline(time.Now().Add(2 * time.Minute))
				}
			}(conn)
		}
	}()
	return nil
}
