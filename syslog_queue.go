package main

import (
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const syslogQueueSlots = 256
const syslogPayloadLimit = 16384

type syslogPacket struct{ Sender, Raw string }
type syslogPressure struct {
	Dropped    atomic.Int64
	LastNotice atomic.Int64
	Origins    atomic.Pointer[map[string]bool]
}

func (a *App) refreshSyslogOriginsLocked() {
	origins := map[string]bool{}
	for _, d := range a.cfg.Devices {
		origins[d.IP] = true
	}
	a.inputPressure.Origins.Store(&origins)
}
func (a *App) syslogOriginAllowed(sender string) bool {
	origins := a.inputPressure.Origins.Load()
	return origins != nil && (*origins)[sender]
}

func (p *syslogPressure) record(sender, reason string, count int64) {
	p.Dropped.Add(count)
	now := time.Now().Unix()
	last := p.LastNotice.Load()
	if now != last && p.LastNotice.CompareAndSwap(last, now) {
		log.Printf("SIEM_INPUT reason=%q sender=%q dropped=%d", reason, sender, count)
	}
}

type syslogQueue struct {
	mu        sync.Mutex
	perOrigin map[string]int
	packets   chan syslogPacket
	done      chan struct{}
	once      sync.Once
	finished  chan struct{}
	consume   func(syslogPacket)
	reject    func(syslogPacket)
}

func newSyslogQueue(size int, consume, reject func(syslogPacket)) *syslogQueue {
	q := &syslogQueue{perOrigin: map[string]int{}, packets: make(chan syslogPacket, size), done: make(chan struct{}), finished: make(chan struct{}), consume: consume, reject: reject}
	go func() {
		defer close(q.finished)
		for {
			select {
			case <-q.done:
				return
			case packet := <-q.packets:
				q.mu.Lock()
				q.perOrigin[packet.Sender]--
				if q.perOrigin[packet.Sender] == 0 {
					delete(q.perOrigin, packet.Sender)
				}
				q.mu.Unlock()
				consume(packet)
			}
		}
	}()
	return q
}
func (q *syslogQueue) enqueue(sender, raw string) bool {
	if len(raw) > syslogPayloadLimit {
		raw = raw[:syslogPayloadLimit]
	}
	// Copy a possibly larger backing buffer: retained bytes are <=slots*16KiB.
	packet := syslogPacket{Sender: sender, Raw: string(append([]byte(nil), raw...))}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.perOrigin[sender] >= 64 {
		q.reject(packet)
		return false
	}
	select {
	case <-q.done:
		return false
	default:
	}
	select {
	case <-q.done:
		return false
	case q.packets <- packet:
		q.perOrigin[sender]++
		return true
	default:
		q.reject(packet)
		return false
	}
}
func (q *syslogQueue) close() { q.once.Do(func() { close(q.done) }) }
func (a *App) accountInputDropsLocked() {
	if count := a.inputPressure.Dropped.Swap(0); count > 0 {
		a.dropped += count
		a.capacitySignal("entrada syslog saturada; descartes de rede/fila: "+formatCount(count), Event{}, false)
	}
}
func formatCount(n int64) string                          { return strconv.FormatInt(n, 10) }
func syslogOverflowDelta(previous, current uint32) uint32 { return current - previous }
func basicSyslogReader(conn net.PacketConn) func([]byte) (int, net.Addr, uint32, error) {
	return func(buf []byte) (int, net.Addr, uint32, error) {
		n, addr, err := conn.ReadFrom(buf)
		return n, addr, 0, err
	}
}
