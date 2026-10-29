//go:build with_gvisor

// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	wgtun "github.com/tailscale/wireguard-go/tun"
)

const regressionAndroidPackage = "com.tailscale.ipn.singbox"

type ownerLookupHost struct {
	*testHost
	mu         sync.Mutex
	interfaces []adapter.NetworkInterface
	owner      adapter.ConnectionOwner
	ownerCalls int
}

func (h *ownerLookupHost) Interfaces() ([]adapter.NetworkInterface, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]adapter.NetworkInterface(nil), h.interfaces...), nil
}

func (h *ownerLookupHost) FindOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ownerCalls++
	owner := h.owner
	owner.AndroidPackageNames = append([]string(nil), h.owner.AndroidPackageNames...)
	return &owner, nil
}

func (h *ownerLookupHost) setInterfaces(interfaces []adapter.NetworkInterface) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.interfaces = append([]adapter.NetworkInterface(nil), interfaces...)
}

func (h *ownerLookupHost) findOwnerCallCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ownerCalls
}

func TestOwnerLookupAfterRestoredInterfaceIsRefreshed(t *testing.T) {
	tests := []struct {
		name          string
		rule          string
		expectAllowed bool
	}{
		{
			name:          "package_name",
			rule:          `{"package_name":"com.tailscale.ipn.singbox","outbound":"direct"}`,
			expectAllowed: true,
		},
		{
			name:          "package_name_regex",
			rule:          `{"package_name_regex":"^com\\.tailscale\\.ipn\\.singbox$","outbound":"direct"}`,
			expectAllowed: true,
		},
		{
			name:          "user_id",
			rule:          `{"user_id":10001,"outbound":"direct"}`,
			expectAllowed: true,
		},
		{
			name:          "package_name_nonmatch",
			rule:          `{"package_name":"com.example.other","outbound":"direct"}`,
			expectAllowed: false,
		},
		{
			name:          "package_name_regex_nonmatch",
			rule:          `{"package_name_regex":"^org\\.example\\..+$","outbound":"direct"}`,
			expectAllowed: false,
		},
		{
			name:          "user_id_nonmatch",
			rule:          `{"user_id":10205,"outbound":"direct"}`,
			expectAllowed: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runOwnerLookupAfterRestoredInterface(t, test.rule, test.expectAllowed)
		})
	}
}

func runOwnerLookupAfterRestoredInterface(t *testing.T, ownerRule string, expectAllowed bool) {
	t.Helper()
	physicalInterface, destinationIP := ownerLookupPhysicalInterface(t)
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: destinationIP.AsSlice()})
	if err != nil {
		t.Fatalf("start local UDP echo server: %v", err)
	}
	defer server.Close()
	go func() {
		buffer := make([]byte, 256)
		n, peer, err := server.ReadFromUDP(buffer)
		if err == nil {
			_, _ = server.WriteToUDP(buffer[:n], peer)
		}
	}()

	host := &ownerLookupHost{
		testHost:   &testHost{defaultIF: &physicalInterface},
		interfaces: []adapter.NetworkInterface{{Interface: physicalInterface}},
		owner: adapter.ConnectionOwner{
			UserId:              10001,
			AndroidPackageNames: []string{regressionAndroidPackage},
		},
	}
	dispatcher := NewDispatcher()
	manager := NewManager(host, dispatcher)
	configuration := `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[` + ownerRule + `,{"action":"reject"}],"final":"direct"}}`
	if err := manager.Apply(configuration); err != nil {
		t.Fatalf("apply owner routing profile: %v", err)
	}
	defer manager.Disable()

	// Model service restoration after the sing-box interface finder took its
	// initial physical-only snapshot. The synthetic Tailscale source becomes
	// visible to the platform host without notifying sing-box's cached finder.
	tunnelInterface := control.Interface{
		Index:     physicalInterface.Index + 10_000,
		MTU:       1280,
		Name:      "tailscale-restore-test",
		Flags:     net.FlagUp | net.FlagPointToPoint,
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.9/32")},
	}
	host.setInterfaces([]adapter.NetworkInterface{
		{Interface: physicalInterface},
		{Interface: tunnelInterface},
	})

	payload := []byte("restored-interface-owner-lookup")
	destination := server.LocalAddr().(*net.UDPAddr)
	packet := ipv4UDPPacket("100.64.0.9", destinationIP.String(), 41001, uint16(destination.Port))
	packet = append(packet, payload...)
	packet[8] = 64
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload)))
	var checksum uint32
	for offset := 0; offset < 20; offset += 2 {
		checksum += uint32(binary.BigEndian.Uint16(packet[offset : offset+2]))
	}
	for checksum>>16 != 0 {
		checksum = (checksum & 0xffff) + (checksum >> 16)
	}
	binary.BigEndian.PutUint16(packet[10:12], ^uint16(checksum))

	device := &returnCapture{
		scriptedDevice: &scriptedDevice{packets: [][]byte{packet}, events: make(chan wgtun.Event)},
		writes:         make(chan []byte, 8),
	}
	wrapped := dispatcher.Wrap(device)
	defer wrapped.Close()
	wrapped.Read(make([]byte, 2048), make([]wgtun.ReadPacket, 32))
	var reply []byte
	select {
	case reply = <-device.writes:
	case <-time.After(time.Second):
		if calls := host.findOwnerCallCount(); calls == 0 {
			t.Fatal("sing-box did not query the platform connection owner for the restored Tailscale source")
		}
		if expectAllowed {
			t.Fatal("matching owner rule did not permit the UDP echo")
		}
		return
	}
	if calls := host.findOwnerCallCount(); calls == 0 {
		t.Fatal("sing-box did not query the platform connection owner for the restored Tailscale source")
	}
	if len(reply) < 20 {
		t.Fatalf("short IP response: %d bytes", len(reply))
	}
	if !expectAllowed {
		if reply[9] == 17 {
			t.Fatal("nonmatching owner rule forwarded UDP traffic")
		}
		if reply[9] != 1 {
			t.Fatalf("nonmatching owner rule response protocol = %d, want ICMP reject", reply[9])
		}
		return
	}
	if reply[9] != 17 {
		t.Fatalf("response protocol = %d, want UDP after owner match", reply[9])
	}
	if len(reply) < 28 {
		t.Fatalf("short UDP reply: %d bytes", len(reply))
	}
	if got := netip.AddrFrom4([4]byte(reply[16:20])); got != netip.MustParseAddr("100.64.0.9") {
		t.Fatalf("reply destination = %v, want 100.64.0.9", got)
	}
	offset := int(reply[0]&15) * 4
	if got := string(reply[offset+8:]); got != string(payload) {
		t.Fatalf("UDP reply payload = %q, want echoed payload", got)
	}
}

func ownerLookupPhysicalInterface(t *testing.T) (control.Interface, netip.Addr) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("list local interfaces: %v", err)
	}
	for _, localInterface := range interfaces {
		if localInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		physical, err := control.InterfaceFromNet(localInterface)
		if err != nil {
			continue
		}
		for _, prefix := range physical.Addresses {
			if prefix.Addr().Is4() && prefix.Addr().IsGlobalUnicast() {
				return physical, prefix.Addr()
			}
		}
	}
	t.Skip("requires one local non-loopback IPv4 interface")
	return control.Interface{}, netip.Addr{}
}
