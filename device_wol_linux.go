//go:build linux

package main

import (
	"net"
	"syscall"
)

func allowWOLBroadcast(conn net.Conn) error {
	raw, err := conn.(*net.UDPConn).SyscallConn()
	if err != nil {
		return err
	}
	var optionErr error
	err = raw.Control(func(fd uintptr) {
		optionErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
	if err != nil {
		return err
	}
	return optionErr
}
