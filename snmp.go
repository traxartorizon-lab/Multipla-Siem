package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

type SNMPClock struct {
	History  []string  `json:"history,omitempty"`
	EngineID string    `json:"engine_id"`
	Boots    uint32    `json:"boots"`
	Ticks    uint32    `json:"ticks"`
	At       time.Time `json:"at"`
}
type snmpDecoder struct {
	Key    string
	Client *gosnmp.GoSNMP
}

func snmpDevice(source SNMPSource) Device {
	return Device{Name: "SNMP · " + source.Name, IP: source.IP, Kind: "snmp"}
}

func (a *App) snmpAddress() string {
	if a.cfg.SNMP != "" {
		return a.cfg.SNMP
	}
	return "0.0.0.0:1162"
}

func newSNMPDecoder(source SNMPSource) (*gosnmp.GoSNMP, error) {
	credentials, err := openDriveToken("snmp:"+source.IP, source.Credentials)
	if err != nil {
		return nil, errors.New("credenciais SNMP indisponíveis")
	}
	decoder := &gosnmp.GoSNMP{Version: gosnmp.Version2c, Community: credentials.Access}
	if source.Version == "v3" {
		engine, err := hex.DecodeString(source.EngineID)
		if err != nil {
			return nil, err
		}
		decoder.Version = gosnmp.Version3
		decoder.MsgFlags = gosnmp.AuthPriv
		decoder.SecurityModel = gosnmp.UserSecurityModel
		decoder.SecurityParameters = &gosnmp.UsmSecurityParameters{UserName: source.User, AuthoritativeEngineID: string(engine), AuthenticationProtocol: gosnmp.SHA256, AuthenticationPassphrase: credentials.Refresh, PrivacyProtocol: gosnmp.AES, PrivacyPassphrase: credentials.Scope}
	}
	return decoder, nil
}

func decodeTrap(decoder *gosnmp.GoSNMP, data []byte) (packet *gosnmp.SnmpPacket, err error) {
	defer func() {
		if recover() != nil {
			packet = nil
			err = errors.New("trap inválido")
		}
	}()
	if len(data) < 8 || len(data) > 8192 {
		return nil, errors.New("tamanho inválido")
	}
	packet, err = decoder.UnmarshalTrap(append([]byte(nil), data...), false)
	if err != nil {
		return nil, errors.New("trap rejeitado")
	}
	if packet.PDUType != gosnmp.SNMPv2Trap || len(packet.Variables) > 128 {
		return nil, errors.New("somente traps v2/v3 com até 128 variáveis")
	}
	if decoder.Version == gosnmp.Version3 {
		security, ok := packet.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		expected := decoder.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		if !ok || packet.Version != gosnmp.Version3 || packet.SecurityModel != gosnmp.UserSecurityModel || packet.MsgFlags&gosnmp.AuthPriv != gosnmp.AuthPriv || security.UserName != expected.UserName || security.AuthoritativeEngineID != expected.AuthoritativeEngineID || security.AuthoritativeEngineBoots >= 2147483647 || security.AuthoritativeEngineTime > 2147483647 || packet.MsgFlags & ^(gosnmp.AuthPriv|gosnmp.Reportable) != 0 {
			return nil, errors.New("SNMPv3 exige authPriv, usuário e engine ID cadastrados")
		}
	} else if packet.Version != gosnmp.Version2c || !equal(packet.Community, decoder.Community) {
		return nil, errors.New("versão ou community inválida")
	}
	return packet, nil
}

func (a *App) acceptTrapClock(source SNMPSource, packet *gosnmp.SnmpPacket, data []byte, now time.Time) bool {
	digest := sha256.Sum256(data)
	key := source.IP + ":" + hex.EncodeToString(digest[:])
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.snmpSeen == nil {
		a.snmpSeen = map[string]time.Time{}
	}
	for k, expiry := range a.snmpSeen {
		if !now.Before(expiry) {
			delete(a.snmpSeen, k)
		}
	}
	if _, seen := a.snmpSeen[key]; seen || len(a.snmpSeen) >= 2048 {
		return false
	}
	if source.Version == "v3" {
		security := packet.SecurityParameters.(*gosnmp.UsmSecurityParameters)
		previous := a.state.SNMPClocks[source.IP]
		for _, saved := range previous.History {
			if saved == key {
				return false
			}
		}
		if previous.EngineID == source.EngineID && !previous.At.IsZero() {
			if security.AuthoritativeEngineBoots < previous.Boots {
				return false
			}
			if security.AuthoritativeEngineBoots == previous.Boots {
				expected := int64(previous.Ticks) + int64(now.Sub(previous.At)/time.Second)
				difference := int64(security.AuthoritativeEngineTime) - expected
				if now.Before(previous.At) || difference < -150 || difference > 150 {
					return false
				}
			}
		}
		if len(a.state.SNMPClocks) >= 64 {
			if _, ok := a.state.SNMPClocks[source.IP]; !ok {
				return false
			}
		}
		updated := SNMPClock{EngineID: source.EngineID, Boots: security.AuthoritativeEngineBoots, Ticks: security.AuthoritativeEngineTime, At: now}
		if previous.EngineID == source.EngineID && previous.Boots == updated.Boots && int64(updated.Ticks) < int64(previous.Ticks)+int64(now.Sub(previous.At)/time.Second) {
			updated.Ticks = previous.Ticks
			updated.At = previous.At
		}
		updated.History = append(append([]string(nil), previous.History...), key)
		if len(updated.History) > 128 {
			updated.History = updated.History[len(updated.History)-128:]
		}
		a.state.SNMPClocks[source.IP] = updated
		if err := a.persist(); err != nil {
			if previous.At.IsZero() {
				delete(a.state.SNMPClocks, source.IP)
			} else {
				a.state.SNMPClocks[source.IP] = previous
			}
			return false
		}
	}
	a.snmpSeen[key] = now.Add(150 * time.Second)
	return true
}

func trapMessage(packet *gosnmp.SnmpPacket) string {
	oid := "unknown"
	parts := []string{}
	for _, variable := range packet.Variables {
		name := "." + strings.TrimPrefix(variable.Name, ".")
		value := fmt.Sprint(variable.Value)
		if bytes, ok := variable.Value.([]byte); ok {
			value = string(bytes)
		}
		if len(value) > 256 {
			value = value[:256]
		}
		if name == ".1.3.6.1.6.3.1.1.4.1.0" {
			oid = "." + strings.TrimPrefix(value, ".")
		}
		parts = append(parts, name+"="+strings.ReplaceAll(strings.ReplaceAll(value, "\r", " "), "\n", " "))
	}
	return "SNMP trap OID=" + oid + " " + strings.Join(parts, " ")
}

func snmpAlert(raw string) (string, int) {
	switch {
	case strings.HasPrefix(raw, "SNMP trap OID=.1.3.6.1.6.3.1.1.5.3 "):
		return "SNMP: interface indisponível (linkDown)", 10
	case strings.HasPrefix(raw, "SNMP trap OID=.1.3.6.1.6.3.1.1.5.5 "):
		return "SNMP: falha de autenticação", 11
	case strings.HasPrefix(raw, "SNMP trap OID=.1.3.6.1.6.3.1.1.5.1 "):
		return "SNMP: dispositivo reiniciado (coldStart)", 6
	case strings.HasPrefix(raw, "SNMP trap OID=.1.3.6.1.6.3.1.1.5.2 "):
		return "SNMP: agente reiniciado (warmStart)", 6
	}
	return "", 0
}

func (a *App) receiveTrap(peer string, data []byte) bool {
	a.snmpMu.Lock()
	defer a.snmpMu.Unlock()
	a.mu.Lock()
	settings := a.state.Receivers
	source := SNMPSource{}
	for _, v := range settings.Sources {
		if v.IP == peer {
			source = v
			break
		}
	}
	a.mu.Unlock()
	if a.demo || !settings.SNMPEnabled || source.IP == "" || !a.takeRate("snmp:global", 120, time.Minute) || !a.takeRate("snmp:"+peer, 30, time.Minute) {
		return false
	}
	if a.snmpDecoders == nil || len(a.snmpDecoders) > 64 {
		a.snmpDecoders = map[string]snmpDecoder{}
	}
	key := source.Version + source.EngineID + source.User + source.Credentials
	cached := a.snmpDecoders[peer]
	if cached.Key != key {
		decoder, err := newSNMPDecoder(source)
		if err != nil {
			return false
		}
		cached = snmpDecoder{key, decoder}
		a.snmpDecoders[peer] = cached
	}
	packet, err := decodeTrap(cached.Client, data)
	if err != nil {
		a.mu.Lock()
		a.snmpStatus = "Trap rejeitado: confira versão, usuário, engine ID e credenciais"
		a.mu.Unlock()
		return false
	}
	if !a.acceptTrapClock(source, packet, data, time.Now().UTC()) {
		a.mu.Lock()
		a.snmpStatus = "Trap repetido, fora da janela de tempo ou armazenamento indisponível"
		a.mu.Unlock()
		return false
	}
	a.mu.Lock()
	a.snmpStatus = "Último trap aceito: " + source.Name
	a.mu.Unlock()
	a.ingest(snmpDevice(source), trapMessage(packet))
	return true
}

func (a *App) snmpWorker() {
	if a.demo {
		return
	}
	address := a.snmpAddress()
	for {
		socket, err := net.ListenPacket("udp", address)
		if err != nil {
			a.mu.Lock()
			a.snmpStatus = "Porta SNMP indisponível; confira configuração e reinicie"
			a.mu.Unlock()
			time.Sleep(10 * time.Second)
			continue
		}
		a.mu.Lock()
		a.snmpStatus = "Receptor UDP disponível"
		a.mu.Unlock()
		a.serveSNMPSocket(socket)
		socket.Close()
	}
}

func (a *App) serveSNMPSocket(socket net.PacketConn) {
	buffer := make([]byte, 8193)
	for {
		n, peer, err := socket.ReadFrom(buffer)
		if err != nil {
			break
		}
		host, _, err := net.SplitHostPort(peer.String())
		if err == nil && n <= 8192 {
			a.receiveTrap(host, buffer[:n])
		}
	}
}
