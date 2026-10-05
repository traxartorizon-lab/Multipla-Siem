package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func validateWebhookURL(target, approved string) error {
	parsed, err := url.Parse(target)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || len(target) > 2048 || strings.ContainsAny(parsed.Hostname(), "%\r\n") {
		return errors.New("webhook exige URL HTTPS sem usuário, query ou fragmento")
	}
	if parsed.Port() != "" {
		port, e := strconv.Atoi(parsed.Port())
		if e != nil || port < 1 || port > 65535 {
			return errors.New("porta inválida")
		}
	}
	if approved != "" {
		ip, e := netip.ParseAddr(approved)
		if e != nil || !ip.IsPrivate() || ip.Unmap().String() != approved {
			return errors.New("IP aprovado deve ser endereço privado exato")
		}
	}
	if ip, e := netip.ParseAddr(parsed.Hostname()); e == nil && !webhookIPAllowed(ip, approved) {
		return errors.New("destino de webhook não permitido")
	}
	return nil
}

func webhookIPAllowed(ip netip.Addr, approved string) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.String() == "100.100.100.200" {
		return false
	}
	if ip.IsPrivate() {
		return ip.String() == approved
	}
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(cidr).Contains(ip) {
			return false
		}
	}
	return true
}

func webhookClient(approved string) *http.Client {
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}, DisableKeepAlives: true, ResponseHeaderTimeout: 5 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		ips, err := resolveWebhookDestination(ctx, host, approved, net.DefaultResolver.LookupNetIP)
		if err != nil {
			return nil, err
		}
		return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return errors.New("redirecionamento recusado") }}
}

func webhookBody(event Event) []byte {
	body, _ := json.Marshal(map[string]any{"product": "Multipla Siem", "version": "1.2.2", "id": event.ID, "time": event.Time, "device": redact(event.Device), "protocol": event.Protocol, "source_ip": event.SourceIP, "level": event.Level, "title": redact(event.Rule)})
	return body
}

func deliverWebhook(ctx context.Context, settings ReceiverSettings, event Event) error {
	return deliverWebhookHTTP(ctx, settings, event, webhookClient(settings.OutboundIP))
}

func deliverWebhookHTTP(ctx context.Context, settings ReceiverSettings, event Event, sender *http.Client) error {
	if err := validateWebhookURL(settings.OutboundURL, settings.OutboundIP); err != nil {
		return err
	}
	credentials, err := openDriveToken("webhook-out", settings.OutboundCredentials)
	if err != nil {
		return errors.New("segredo indisponível")
	}
	body := webhookBody(event)
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(credentials.Access))
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	request, err := http.NewRequestWithContext(ctx, "POST", settings.OutboundURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Multipla-Timestamp", timestamp)
	request.Header.Set("X-Multipla-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	request.Header.Set("X-Multipla-Event-ID", event.ID)
	response, err := sender.Do(request)
	if err != nil {
		return errors.New("envio indisponível ou destino recusado")
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("destino respondeu HTTP %d", response.StatusCode)
	}
	return nil
}

func (a *App) queueWebhook(event Event) {
	settings := a.state.Receivers
	threshold := settings.OutboundLevel
	if threshold == 0 {
		threshold = 10
	}
	if a.demo || !event.Alert || !settings.OutboundEnabled || event.Level < threshold {
		return
	}
	select {
	case a.webhookQ <- event:
	default:
		a.webhookStatus = "Fila cheia; notificação descartada"
	}
}

func (a *App) webhookWorker() {
	for event := range a.webhookQ {
		a.mu.Lock()
		settings := a.state.Receivers
		a.mu.Unlock()
		if a.demo || !settings.OutboundEnabled {
			continue
		}
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			a.mu.Lock()
			current := a.state.Receivers
			a.mu.Unlock()
			if !current.OutboundEnabled || current.OutboundURL != settings.OutboundURL || current.OutboundCredentials != settings.OutboundCredentials || current.OutboundIP != settings.OutboundIP {
				err = errors.New("envio cancelado após mudança de configuração")
				break
			}
			err = deliverWebhook(context.Background(), settings, event)
			if err == nil {
				break
			}
			if attempt < 2 {
				time.Sleep(time.Duration(attempt+1) * time.Second)
			}
		}
		status := "Enviado com sucesso"
		if err != nil {
			status = "Falha após três tentativas: " + err.Error()
		}
		a.mu.Lock()
		a.webhookStatus = status
		a.audit("webhook", status)
		a.persist()
		a.mu.Unlock()
	}
}

func (a *App) receiveWebhook(w http.ResponseWriter, r *http.Request) {
	peer := a.clientIP(r)
	a.mu.Lock()
	settings := a.state.Receivers
	a.mu.Unlock()
	allowed := false
	for _, ip := range settings.InboundIPs {
		if ip == peer {
			allowed = true
			break
		}
	}
	if a.demo || !settings.InboundEnabled || !allowed {
		http.Error(w, "origem não autorizada", 403)
		return
	}
	credentials, err := openDriveToken("webhook-in", settings.InboundCredentials)
	if err != nil || !equal("Bearer "+credentials.Access, r.Header.Get("Authorization")) {
		http.Error(w, "token inválido", 403)
		return
	}
	var input struct {
		Message  string `json:"message"`
		Title    string `json:"title"`
		Level    int    `json:"level"`
		SourceIP string `json:"source_ip"`
	}
	if !decode(w, r, &input) {
		return
	}
	if input.Level < 1 || input.Level > 15 || len(input.Message) > 16384 || len(input.Message) == 0 || len(input.Title) > 256 || (input.SourceIP != "" && !sourceAddress(input.SourceIP)) {
		http.Error(w, "evento inválido", 400)
		return
	}
	title := input.Title
	if title == "" {
		title = "Alerta recebido por webhook"
	}
	event := Event{ID: token(), Time: time.Now().UTC(), Kind: "webhook", Protocol: "webhook", SenderIP: peer, Device: "Webhook " + peer, SourceIP: input.SourceIP, Message: redact(input.Message), Rule: redact(title), Level: input.Level, Alert: true, Detector: "webhook"}
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.appendEvent(event) {
		http.Error(w, "falha no armazenamento", 503)
		return
	}
	a.evaluateRules(event, input.Message, Device{Name: event.Device, IP: peer, Kind: "webhook"})
	if event.Level >= a.cfg.MailMinLevel {
		select {
		case a.mailQ <- event:
		default:
			a.mailStatus = "Fila cheia"
		}
	}
	writeJSON(w, map[string]string{"id": event.ID})
}

func resolveWebhookDestination(ctx context.Context, host, approved string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	ips, err := lookup(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("destino indisponível")
	}
	for _, ip := range ips {
		if !webhookIPAllowed(ip, approved) {
			return nil, errors.New("destino não permitido")
		}
	}
	return ips, nil
}
