// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"encoding/binary"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	singtun "github.com/sagernet/sing-tun"
	wgtun "github.com/tailscale/wireguard-go/tun"
)

// packetPort is an in-process interface, never an additional Android VPN.
// A full queue drops packets rather than blocking the tailnet packet reader.
type packetPort struct {
	packets chan []byte
	done    chan struct{}
	once    sync.Once
	write   func([]byte) (int, error)
}

func newPacketPort(write func([]byte) (int, error)) *packetPort {
	return &packetPort{packets: make(chan []byte, 256), done: make(chan struct{}), write: write}
}
func (p *packetPort) Read(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, io.ErrClosedPipe
	case packet := <-p.packets:
		if len(packet) > len(b) {
			return 0, io.ErrShortBuffer
		}
		return copy(b, packet), nil
	}
}
func (p *packetPort) Write(b []byte) (int, error) {
	select {
	case <-p.done:
		return 0, io.ErrClosedPipe
	default:
		return p.write(b)
	}
}
func (p *packetPort) Close() error                             { p.once.Do(func() { close(p.done) }); return nil }
func (p *packetPort) Start() error                             { return nil }
func (p *packetPort) Name() (string, error)                    { return "tailscale-singbox", nil }
func (p *packetPort) UpdateRouteOptions(singtun.Options) error { return nil }
func (p *packetPort) offer(b []byte) {
	select {
	case <-p.done:
		return
	default:
	}
	select {
	case p.packets <- append([]byte(nil), b...):
	default:
	}
}

type routeTable struct{ prefixes []netip.Prefix }

// Dispatcher has one physical TUN reader (the existing WireGuard reader).
// Both engines' return paths serialize writes to the current Android device.
type Dispatcher struct {
	routes     atomic.Pointer[routeTable]
	port       atomic.Pointer[packetPort]
	enabled    atomic.Bool
	mu         sync.Mutex
	writeMu    sync.Mutex
	current    *splitDevice
	flowMu     sync.Mutex
	flows      map[flowKey]flowState
	flowChecks uint64
}

func NewDispatcher() *Dispatcher { return &Dispatcher{flows: make(map[flowKey]flowState)} }
func (d *Dispatcher) SetRoutes(routes []netip.Prefix) {
	filtered := make([]netip.Prefix, 0, len(routes))
	for _, p := range routes {
		if p.IsValid() && p.Bits() != 0 {
			filtered = append(filtered, p)
		}
	}
	d.routes.Store(&routeTable{filtered})
}
func (d *Dispatcher) SetEnabled(enabled bool) {
	d.enabled.Store(enabled)
	if !enabled {
		d.flowMu.Lock()
		clear(d.flows)
		d.flowMu.Unlock()
	}
}
func (d *Dispatcher) newPort() *packetPort  { return newPacketPort(d.writePacket) }
func (d *Dispatcher) setPort(p *packetPort) { d.port.Store(p) }
func (d *Dispatcher) writePacket(b []byte) (int, error) {
	d.mu.Lock()
	device := d.current
	d.mu.Unlock()
	if device == nil {
		return 0, io.ErrClosedPipe
	}
	d.writeMu.Lock()
	_, err := device.Device.Write([][]byte{b}, 0)
	d.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
func (d *Dispatcher) Wrap(dev wgtun.Device) wgtun.Device {
	wrapped := &splitDevice{Device: dev, dispatcher: d}
	d.mu.Lock()
	d.current = wrapped
	d.mu.Unlock()
	return wrapped
}
func (d *Dispatcher) CloseCurrent() error {
	d.mu.Lock()
	current := d.current
	d.mu.Unlock()
	if current != nil {
		return current.Close()
	}
	return nil
}
func (d *Dispatcher) bypass(packet []byte) bool {
	var addr netip.Addr
	if len(packet) > 0 {
		switch packet[0] >> 4 {
		case 4:
			if len(packet) >= 20 {
				addr = netip.AddrFrom4([4]byte(packet[16:20]))
			}
		case 6:
			if len(packet) >= 40 {
				addr = netip.AddrFrom16([16]byte(packet[24:40]))
			}
		}
	}
	if !addr.IsValid() {
		return false
	}
	// All DNS to the Android resolver enters sing-box, including the Tailscale
	// service address. Its native transport delegates private names in-process.
	if addr == netip.MustParseAddr("100.100.100.100") || addr == netip.MustParseAddr("fd7a:115c:a1e0::53") {
		return false
	}
	if routes := d.routes.Load(); routes != nil {
		for _, p := range routes.prefixes {
			if p.Contains(addr) {
				return true
			}
		}
	}
	return false
}

type splitDevice struct {
	wgtun.Device
	dispatcher *Dispatcher
	closeOnce  sync.Once
	closeErr   error
}

func (d *splitDevice) Read(slab []byte, packets []wgtun.ReadPacket) (int, error) {
	for {
		n, err := d.Device.Read(slab, packets)
		kept := 0
		for _, p := range packets[:n] {
			packet := slab[p.Offset : p.Offset+p.Size]
			engine := d.dispatcher.engineFor(packet)
			if engine == 1 {
				packets[kept] = p
				kept++
			} else if port := d.dispatcher.port.Load(); engine == 2 && port != nil {
				port.offer(packet)
			}
		}
		if kept > 0 || err != nil {
			return kept, err
		}
	}
}

type flowKey struct {
	source, destination         netip.Addr
	protocol                    uint8
	sourcePort, destinationPort uint16
}
type flowState struct {
	engine   uint8
	lastSeen time.Time
}

func parseFlow(packet []byte) (flowKey, bool) {
	var key flowKey
	var offset int
	if len(packet) == 0 {
		return key, false
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) < 20 {
			return key, false
		}
		offset = int(packet[0]&15) * 4
		if offset < 20 || len(packet) < offset {
			return key, false
		}
		key.source = netip.AddrFrom4([4]byte(packet[12:16]))
		key.destination = netip.AddrFrom4([4]byte(packet[16:20]))
		key.protocol = packet[9]
		// All fragments of an IPv4 datagram share the address/protocol key.
		if binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return key, true
		}
	case 6:
		if len(packet) < 40 {
			return key, false
		}
		offset = 40
		key.source = netip.AddrFrom16([16]byte(packet[8:24]))
		key.destination = netip.AddrFrom16([16]byte(packet[24:40]))
		key.protocol = packet[6]
	default:
		return key, false
	}
	if (key.protocol == 6 || key.protocol == 17) && len(packet) >= offset+4 {
		key.sourcePort = binary.BigEndian.Uint16(packet[offset:])
		key.destinationPort = binary.BigEndian.Uint16(packet[offset+2:])
	}
	return key, true
}

// Existing flows never switch engines after a route update. A flow whose
// selected path changes is blocked until it expires rather than sent direct.
func (d *Dispatcher) engineFor(packet []byte) uint8 {
	if !d.enabled.Load() {
		return 1
	}
	key, ok := parseFlow(packet)
	if !ok {
		return 0
	}
	engine := uint8(2)
	if d.bypass(packet) {
		engine = 1
	}
	now := time.Now()
	d.flowMu.Lock()
	defer d.flowMu.Unlock()
	d.flowChecks++
	if d.flowChecks%1024 == 0 {
		for key, state := range d.flows {
			idle := 2 * time.Minute
			if key.protocol == 6 {
				idle = 2 * time.Hour
			}
			if now.Sub(state.lastSeen) > idle {
				delete(d.flows, key)
			}
		}
	}
	if state, exists := d.flows[key]; exists {
		state.lastSeen = now
		d.flows[key] = state
		if state.engine != engine {
			return 0
		}
		return state.engine
	}
	if len(d.flows) >= 16384 {
		return 0
	}
	d.flows[key] = flowState{engine: engine, lastSeen: now}
	return engine
}
func (d *splitDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.dispatcher.writeMu.Lock()
	defer d.dispatcher.writeMu.Unlock()
	return d.Device.Write(bufs, offset)
}
func (d *splitDevice) Close() error {
	d.closeOnce.Do(func() {
		d.dispatcher.mu.Lock()
		if d.dispatcher.current == d {
			d.dispatcher.current = nil
		}
		d.dispatcher.mu.Unlock()
		d.closeErr = d.Device.Close()
	})
	return d.closeErr
}
