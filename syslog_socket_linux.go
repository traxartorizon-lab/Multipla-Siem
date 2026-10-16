//go:build linux

package main

import (
	"encoding/binary"
	"log"
	"net"
	"syscall"
)

func syslogPacketReader(conn net.PacketConn) func([]byte) (int, net.Addr, uint32, error) {
	udp, ok := conn.(*net.UDPConn)
	if !ok {
		return basicSyslogReader(conn)
	}
	raw, err := udp.SyscallConn()
	var optionErr error
	if err == nil {
		err = raw.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RXQ_OVFL, 1)
		})
	}
	if err == nil {
		err = optionErr
	}
	if err != nil {
		log.Printf("SIEM_INPUT kernel_overflow_monitor_unavailable=%q", err)
		return basicSyslogReader(conn)
	}
	var previous uint32
	control := make([]byte, 64)
	return func(buf []byte) (int, net.Addr, uint32, error) {
		n, oobn, _, addr, err := udp.ReadMsgUDP(buf, control)
		var dropped uint32
		messages, _ := syscall.ParseSocketControlMessage(control[:oobn])
		for _, m := range messages {
			if m.Header.Level == syscall.SOL_SOCKET && m.Header.Type == syscall.SO_RXQ_OVFL && len(m.Data) >= 4 {
				value := binary.NativeEndian.Uint32(m.Data)
				dropped = syslogOverflowDelta(previous, value)
				previous = value
			}
		}
		return n, addr, dropped, err
	}
}
