// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	wgtun "github.com/tailscale/wireguard-go/tun"
)

func TestDispatcherBypassesTailnetAndAcceptedSubnetsForBothIPFamilies(t *testing.T) {
	packets := [][]byte{
		ipv4Packet("192.0.2.10", "100.67.2.4"),
		ipv4Packet("192.0.2.10", "10.42.1.22"),
		ipv4Packet("192.0.2.10", "1.1.1.1"),
		ipv6Packet("2001:db8::10", "fd7a:115c:a1e0::20"),
		ipv6Packet("2001:db8::10", "fd00:1234::1"),
		ipv6Packet("2001:db8::10", "2606:4700:4700::1111"),
	}
	physical := &scriptedDevice{packets: packets, events: make(chan wgtun.Event)}
	dispatcher := NewDispatcher()
	dispatcher.SetRoutes([]netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("fd00::/8"),
	})
	dispatcher.SetEnabled(true)
	port := dispatcher.newPort()
	dispatcher.setPort(port)
	device := dispatcher.Wrap(physical)

	slab := make([]byte, 4096)
	readPackets := make([]wgtun.ReadPacket, 8)
	n, err := device.Read(slab, readPackets)
	if err != nil {
		t.Fatalf("splitDevice.Read() error = %v", err)
	}
	if n != 4 {
		t.Fatalf("Tailscale TUN received %d packets, want 4 (two tailnet and two accepted-subnet packets)", n)
	}
	wantBypass := []string{"100.67.2.4", "10.42.1.22", "fd7a:115c:a1e0::20", "fd00:1234::1"}
	for i, want := range wantBypass {
		p := readPackets[i]
		got := destinationAddress(slab[p.Offset : p.Offset+p.Size])
		if got != want {
			t.Errorf("Tailscale packet %d destination = %q, want %q", i, got, want)
		}
	}

	wantSingBox := []string{"1.1.1.1", "2606:4700:4700::1111"}
	buf := make([]byte, 128)
	for _, want := range wantSingBox {
		n, err := port.Read(buf)
		if err != nil {
			t.Fatalf("sing-box packet read: %v", err)
		}
		got := destinationAddress(buf[:n])
		if got != want {
			t.Errorf("sing-box packet destination = %q, want %q", got, want)
		}
	}
	_ = port.Close()
	_ = device.Close()
}

func TestDispatcherQueueIsBoundedAndPortsClose(t *testing.T) {
	port := newPacketPort(func(b []byte) (int, error) { return len(b), nil })
	original := []byte{42}
	port.offer(original)
	original[0] = 99
	for i := 0; i < cap(port.packets)+32; i++ {
		port.offer([]byte{byte(i)})
	}
	if got, want := len(port.packets), cap(port.packets); got != want {
		t.Fatalf("queued packets = %d, want bounded capacity %d", got, want)
	}
	first := make([]byte, 1)
	n, err := port.Read(first)
	if err != nil || n != 1 || first[0] != 42 {
		t.Fatalf("first Read() = (%d, %v), packet=%v; want cloned original byte 42", n, err, first)
	}
	for len(port.packets) > 0 {
		if _, err := port.Read(make([]byte, 1)); err != nil {
			t.Fatalf("drain queued packet: %v", err)
		}
	}
	if err := port.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := port.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Read after close error = %v, want io.ErrClosedPipe", err)
	}
	if _, err := port.Write([]byte{1}); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("Write after close error = %v, want io.ErrClosedPipe", err)
	}
}

func TestExistingFlowBlocksUntilItsOriginalRouteRecovers(t *testing.T) {
	dispatcher := NewDispatcher()
	dispatcher.SetEnabled(true)
	dispatcher.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})

	tailnetFlow := ipv4TCPPacket("192.0.2.10", "100.67.2.4", 41000, 443)
	if got := dispatcher.engineFor(tailnetFlow); got != 1 {
		t.Fatalf("initial tailnet flow engine = %d, want Tailscale (1)", got)
	}

	// Removing the route changes this tuple's classification to sing-box. The
	// established flow must stop instead of silently switching transports.
	dispatcher.SetRoutes(nil)
	if got := dispatcher.engineFor(tailnetFlow); got != 0 {
		t.Fatalf("changed tailnet flow engine = %d, want blocked (0)", got)
	}
	// The original engine is allowed to resume once its route recovers.
	dispatcher.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})
	if got := dispatcher.engineFor(tailnetFlow); got != 1 {
		t.Fatalf("restored tailnet flow engine = %d, want original Tailscale engine (1)", got)
	}

	newInternetFlow := ipv4TCPPacket("192.0.2.10", "1.1.1.1", 41001, 443)
	if got := dispatcher.engineFor(newInternetFlow); got != 2 {
		t.Fatalf("new Internet flow engine = %d, want sing-box (2)", got)
	}

	// An Internet flow also remains associated with its original engine when
	// a newly installed Tailscale route temporarily changes classification.
	dispatcher.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("1.1.1.0/24")})
	if got := dispatcher.engineFor(newInternetFlow); got != 0 {
		t.Fatalf("Internet flow under changed route = %d, want blocked (0)", got)
	}
	dispatcher.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})
	if got := dispatcher.engineFor(newInternetFlow); got != 2 {
		t.Fatalf("restored Internet flow engine = %d, want original sing-box engine (2)", got)
	}
}

func TestExistingUDPFlowBlocksUntilItsOriginalRouteRecovers(t *testing.T) {
	dispatcher := NewDispatcher()
	dispatcher.SetEnabled(true)
	dispatcher.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})

	flow := ipv4UDPPacket("192.0.2.10", "100.67.2.4", 53000, 53)
	if got := dispatcher.engineFor(flow); got != 1 {
		t.Fatalf("initial UDP flow engine = %d, want Tailscale (1)", got)
	}
	dispatcher.SetRoutes(nil)
	if got := dispatcher.engineFor(flow); got != 0 {
		t.Fatalf("UDP flow while route is unavailable = %d, want blocked (0)", got)
	}
	dispatcher.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})
	if got := dispatcher.engineFor(flow); got != 1 {
		t.Fatalf("UDP flow after route recovery = %d, want original Tailscale engine (1)", got)
	}
}

func TestWrappedCloseUnblocksConcurrentPacketWriter(t *testing.T) {
	device := &blockingWriteDevice{
		scriptedDevice: &scriptedDevice{events: make(chan wgtun.Event)},
		writeStarted:   make(chan struct{}),
		writeUnblocked: make(chan struct{}),
	}
	dispatcher := NewDispatcher()
	wrapped := dispatcher.Wrap(device)

	writeDone := make(chan error, 1)
	go func() {
		_, err := dispatcher.writePacket([]byte{0x45})
		writeDone <- err
	}()
	select {
	case <-device.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("packet writer did not reach the blocked device write")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- wrapped.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("wrapped Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wrapped Close() blocked behind an in-progress packet writer")
	}
	select {
	case err := <-writeDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("packet writer error = %v, want io.ErrClosedPipe after device close", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the wrapped TUN did not unblock the packet writer")
	}
}

func TestReplacementUnblocksSingBoxAndWaitingWireGuardWriters(t *testing.T) {
	oldDevice := &blockingWriteDevice{
		scriptedDevice: &scriptedDevice{events: make(chan wgtun.Event)},
		writeStarted:   make(chan struct{}),
		writeUnblocked: make(chan struct{}),
	}
	dispatcher := NewDispatcher()
	oldWrapped := dispatcher.Wrap(oldDevice)
	port := dispatcher.newPort()

	singBoxWriteDone := make(chan error, 1)
	go func() { _, err := port.Write([]byte{0x45}); singBoxWriteDone <- err }()
	select {
	case <-oldDevice.writeStarted:
	case <-time.After(time.Second):
		t.Fatal("sing-box writer did not block in the old device")
	}

	newDevice := &scriptedDevice{events: make(chan wgtun.Event)}
	newWrapped := dispatcher.Wrap(newDevice)

	wireGuardWriteDone := make(chan error, 1)
	go func() {
		_, err := newWrapped.Write([][]byte{{0x45}}, 0)
		wireGuardWriteDone <- err
	}()
	// The multiTUN driver first marks retirement, then closes the wrapper.
	// Wrap itself must not close an FD before that retirement marker exists.
	_ = oldWrapped.Close()
	select {
	case err := <-singBoxWriteDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("old sing-box writer error = %v, want closed-pipe after replacement", err)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement did not unblock the sing-box writer on the old device")
	}
	select {
	case err := <-wireGuardWriteDone:
		if err != nil {
			t.Errorf("new WireGuard writer error = %v, want success on replacement device", err)
		}
	case <-time.After(time.Second):
		t.Fatal("new WireGuard writer remained blocked behind the retired device")
	}
	_ = newWrapped.Close()
}

type scriptedDevice struct {
	packets [][]byte
	events  chan wgtun.Event
	closed  bool
}

type blockingWriteDevice struct {
	*scriptedDevice
	writeStarted   chan struct{}
	writeUnblocked chan struct{}
}

func (d *blockingWriteDevice) Write([][]byte, int) (int, error) {
	close(d.writeStarted)
	<-d.writeUnblocked
	return 0, io.ErrClosedPipe
}
func (d *blockingWriteDevice) Close() error {
	d.scriptedDevice.closed = true
	close(d.writeUnblocked)
	close(d.events)
	return nil
}

func (d *scriptedDevice) Read(slab []byte, out []wgtun.ReadPacket) (int, error) {
	if d.closed {
		return 0, io.ErrClosedPipe
	}
	if len(d.packets) == 0 {
		return 0, io.EOF
	}
	count := len(d.packets)
	if count > len(out) {
		count = len(out)
	}
	offset := wgtun.ReadPacketSpacing
	for i := 0; i < count; i++ {
		packet := d.packets[i]
		if offset+len(packet)+wgtun.ReadPacketSpacing > len(slab) {
			return i, wgtun.ErrTooManySegments
		}
		copy(slab[offset:], packet)
		out[i] = wgtun.ReadPacket{Offset: offset, Size: len(packet)}
		offset += len(packet) + wgtun.ReadPacketSpacing
	}
	d.packets = d.packets[count:]
	return count, nil
}
func (*scriptedDevice) File() *os.File                          { return nil }
func (*scriptedDevice) Write(bufs [][]byte, _ int) (int, error) { return len(bufs), nil }
func (*scriptedDevice) MTU() (int, error)                       { return 1280, nil }
func (*scriptedDevice) Name() (string, error)                   { return "scripted", nil }
func (d *scriptedDevice) Events() <-chan wgtun.Event            { return d.events }
func (d *scriptedDevice) Close() error                          { d.closed = true; close(d.events); return nil }
func (*scriptedDevice) BatchSize() int                          { return 32 }

func ipv4Packet(source, destination string) []byte {
	packet := make([]byte, 20)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = byte(len(packet))
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	return packet
}

func ipv4TCPPacket(source, destination string, sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 24)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = byte(len(packet))
	packet[9] = 6
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	packet[20] = byte(sourcePort >> 8)
	packet[21] = byte(sourcePort)
	packet[22] = byte(destinationPort >> 8)
	packet[23] = byte(destinationPort)
	return packet
}

func ipv4UDPPacket(source, destination string, sourcePort, destinationPort uint16) []byte {
	packet := make([]byte, 28)
	packet[0] = 0x45
	packet[2] = 0
	packet[3] = byte(len(packet))
	packet[9] = 17
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	packet[20] = byte(sourcePort >> 8)
	packet[21] = byte(sourcePort)
	packet[22] = byte(destinationPort >> 8)
	packet[23] = byte(destinationPort)
	packet[24] = 0
	packet[25] = 8
	return packet
}

func ipv6Packet(source, destination string) []byte {
	packet := make([]byte, 40)
	packet[0] = 0x60
	copy(packet[8:24], netip.MustParseAddr(source).AsSlice())
	copy(packet[24:40], netip.MustParseAddr(destination).AsSlice())
	return packet
}

func destinationAddress(packet []byte) string {
	switch packet[0] >> 4 {
	case 4:
		var raw [4]byte
		copy(raw[:], packet[16:20])
		return netip.AddrFrom4(raw).String()
	case 6:
		var raw [16]byte
		copy(raw[:], packet[24:40])
		return netip.AddrFrom16(raw).String()
	default:
		return "invalid"
	}
}
