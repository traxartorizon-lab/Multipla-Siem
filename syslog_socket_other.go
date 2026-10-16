//go:build !linux

package main

import "net"

func syslogPacketReader(conn net.PacketConn) func([]byte) (int, net.Addr, uint32, error) {
	return basicSyslogReader(conn)
}
