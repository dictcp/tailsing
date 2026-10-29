//go:build with_gvisor

// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/control"
	wgtun "github.com/tailscale/wireguard-go/tun"
)

type returnCapture struct {
	*scriptedDevice
	writes chan []byte
}

func (d *returnCapture) Write(packets [][]byte, offset int) (int, error) {
	for _, packet := range packets {
		d.writes <- append([]byte(nil), packet[offset:]...)
	}
	return len(packets), nil
}

// This exercises actual packet ingress, the sing-box UDP flow, a controlled
// physical socket, and packet egress through the same dispatcher writer.
func TestVirtualTUNUDPReplyReachesAndroidWriter(t *testing.T) {
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var hostInterface control.Interface
	var destinationIP netip.Addr
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		value, err := control.InterfaceFromNet(i)
		if err != nil {
			continue
		}
		for _, p := range value.Addresses {
			if p.Addr().Is4() && p.Addr().IsGlobalUnicast() {
				hostInterface = value
				destinationIP = p.Addr()
				break
			}
		}
		if destinationIP.IsValid() {
			break
		}
	}
	if !destinationIP.IsValid() {
		t.Skip("requires one local non-loopback IPv4 interface")
	}
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: destinationIP.AsSlice()})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 256)
		n, peer, err := server.ReadFromUDP(buffer)
		if err == nil {
			server.WriteToUDP(buffer[:n], peer)
		}
	}()
	host := &testHost{defaultIF: &hostInterface}
	dispatcher := NewDispatcher()
	manager := NewManager(host, dispatcher)
	if err := manager.Apply(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`); err != nil {
		t.Fatal(err)
	}
	defer manager.Disable()
	payload := []byte("virtual-tun-echo")
	destination := server.LocalAddr().(*net.UDPAddr)
	packet := ipv4UDPPacket("100.64.0.9", destinationIP.String(), 41001, uint16(destination.Port))
	packet = append(packet, payload...)
	packet[8] = 64
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
	device := &returnCapture{scriptedDevice: &scriptedDevice{packets: [][]byte{packet}, events: make(chan wgtun.Event)}, writes: make(chan []byte, 8)}
	wrapped := dispatcher.Wrap(device)
	defer wrapped.Close()
	// splitDevice.Read consumes the non-tailnet packet then reaches the test
	// device's EOF; the virtual gVisor endpoint handles it asynchronously.
	wrapped.Read(make([]byte, 2048), make([]wgtun.ReadPacket, 32))
	select {
	case reply := <-device.writes:
		if len(reply) < 28 {
			t.Fatalf("short reply %d", len(reply))
		}
		if got := netip.AddrFrom4([4]byte(reply[16:20])); got != netip.MustParseAddr("100.64.0.9") {
			t.Fatalf("reply destination %v", got)
		}
		offset := int(reply[0]&15) * 4
		if string(reply[offset+8:]) != string(payload) {
			t.Fatalf("reply payload %q", reply[offset+8:])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no UDP reply traversed the virtual TUN and Android writer")
	}
	if host.protectedFDCount() == 0 {
		t.Fatal("physical UDP socket was not protected")
	}
}
