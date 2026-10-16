package main

import (
	"strings"
	"testing"
	"time"
)

func TestSyslogQueueBoundedBytesOverflowAndShutdown(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	reject := make(chan syslogPacket, 8)
	q := newSyslogQueue(2, func(packet syslogPacket) {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
	}, func(packet syslogPacket) { reject <- packet })
	// Use a buffered start signal independently from scheduling the consumer.
	if !q.enqueue("100.64.0.1", strings.Repeat("x", 65536)) {
		t.Fatal("first queue entry")
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("consumer did not start")
	}
	for i := 0; i < 2; i++ {
		if !q.enqueue("100.64.0.1", strings.Repeat("x", 65536)) {
			t.Fatal("queue prematurely full")
		}
	}
	if q.enqueue("100.64.0.1", "overflow") {
		t.Fatal("overflow accepted")
	}
	select {
	case <-reject:
	default:
		t.Fatal("overflow not signaled")
	}
	if len(q.packets) != 2 {
		t.Fatal("unbounded queue")
	}
	for i := 0; i < 2; i++ {
		packet := <-q.packets
		if len(packet.Raw) != syslogPayloadLimit {
			t.Fatal("retained payload exceeds cap")
		}
	}
	q.close()
	q.close()
	if q.enqueue("100.64.0.1", "after close") {
		t.Fatal("accepted after close")
	}
	close(release)
	select {
	case <-q.finished:
	case <-time.After(3 * time.Second):
		t.Fatal("worker leaked")
	}
}
func TestSyslogPressureAccounting(t *testing.T) {
	a := testApp(t)
	a.inputPressure.record("100.64.0.1", "udp_queue_full", 7)
	a.inputPressure.record("100.64.0.1", "tcp_connection_limit", 2)
	a.accountInputDropsLocked()
	if a.dropped != 9 {
		t.Fatal("input losses absent from counter", a.dropped)
	}
	a.accountInputDropsLocked()
	if a.dropped != 9 {
		t.Fatal("input losses double counted")
	}
}
func TestRepetitionRFC5424TransportTimestampOnly(t *testing.T) {
	e := repeatSeed(time.Now())
	e.Message = "<13>1 2026-10-14T12:34:55.574364-03:00 MULTIPLAFW app 510 - - Reloading filter dstport=22"
	same := e
	same.Message = strings.Replace(e.Message, "12:34:55.574364", "13:40:12.987654", 1)
	if problemKey(e) != problemKey(same) {
		t.Fatal("RFC5424 timestamp changes repeat identity")
	}
	for _, replacement := range []struct{ old, new string }{{"<13>1", "<13>2"}, {"app 510", "app 511"}, {"dstport=22", "dstport=23"}, {"MULTIPLAFW", "OTHERFW"}} {
		different := e
		different.Message = strings.Replace(e.Message, replacement.old, replacement.new, 1)
		if problemKey(e) == problemKey(different) {
			t.Fatal("semantic RFC5424 field collapsed", replacement)
		}
	}
}
