//go:build !linux

package main

import (
	"errors"
	"net"
)

func allowWOLBroadcast(conn net.Conn) error {
	return errors.New("Wake-on-LAN disponível no servidor Linux")
}
