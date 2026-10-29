// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
)

func TestAndroidInterfaceSnapshotCarriesNetworkConditions(t *testing.T) {
	interfaces, err := ParseNetworkInterfacesJSON([]byte(`[
		{"name":"wlan0","index":4,"mtu":1500,"up":true,"type":"wifi","expensive":false,"constrained":false,"addrs":[{"ip":"192.168.1.5","prefixLen":24}]},
		{"name":"rmnet0","index":5,"mtu":1500,"up":true,"type":"cellular","expensive":true,"constrained":true,"addrs":[{"ip":"2001:db8::5","prefixLen":64}]},
		{"name":"eth0","index":6,"mtu":1500,"up":true,"type":"ethernet","expensive":true,"constrained":false,"addrs":[]},
		{"name":"tun0","index":7,"mtu":1280,"up":true,"addrs":[]}
	]`))
	if err != nil {
		t.Fatal(err)
	}
	if len(interfaces) != 4 {
		t.Fatalf("interfaces count = %d, want 4", len(interfaces))
	}
	for i, want := range []struct {
		typ                    C.InterfaceType
		expensive, constrained bool
	}{
		{C.InterfaceTypeWIFI, false, false},
		{C.InterfaceTypeCellular, true, true},
		{C.InterfaceTypeEthernet, true, false},
		{C.InterfaceTypeOther, false, false},
	} {
		got := interfaces[i]
		if got.Type != want.typ || got.Expensive != want.expensive || got.Constrained != want.constrained {
			t.Errorf("%s metadata = (%s, expensive=%v, constrained=%v), want (%s, %v, %v)", got.Name, got.Type, got.Expensive, got.Constrained, want.typ, want.expensive, want.constrained)
		}
	}
	if got := interfaces[0].Addresses; len(got) != 1 || got[0] != netip.MustParsePrefix("192.168.1.5/24") {
		t.Errorf("Wi-Fi addresses = %v, want preserved host prefix", got)
	}
}

type networkConditionHost struct {
	testHost
	snapshotMu sync.Mutex
	snapshot   string
}

func (h *networkConditionHost) Interfaces() ([]adapter.NetworkInterface, error) {
	h.snapshotMu.Lock()
	defer h.snapshotMu.Unlock()
	return ParseNetworkInterfacesJSON([]byte(h.snapshot))
}

func (h *networkConditionHost) DefaultInterface() *control.Interface {
	interfaces, _ := h.Interfaces()
	if len(interfaces) == 0 {
		return nil
	}
	return &interfaces[0].Interface
}

func (h *networkConditionHost) setSnapshot(snapshot string) {
	h.snapshotMu.Lock()
	defer h.snapshotMu.Unlock()
	h.snapshot = snapshot
}

func TestEngineNetworkConditionsRefreshWithoutDNSChange(t *testing.T) {
	host := &networkConditionHost{}
	host.setSnapshot(`[{"name":"wlan0","index":4,"mtu":1500,"up":true,"type":"wifi","addrs":[{"ip":"192.168.1.5","prefixLen":24}]}]`)
	manager := NewManager(host, NewDispatcher())
	if err := manager.Apply(`{
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"rules":[
			{"network_type":"wifi","action":"reject"},
			{"network_is_expensive":true,"action":"reject"},
			{"network_is_constrained":true,"action":"reject"},
			{"network_type":"cellular","action":"reject"},
			{"network_interface_address":{"wifi":["192.168.1.0/24"]},"action":"reject"}
		],"final":"direct"}
	}`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Disable() })
	check := func(want []bool) {
		t.Helper()
		for i, rule := range manager.box.Router().Rules()[1:] {
			if got := rule.Match(&adapter.InboundContext{}); got != want[i] {
				t.Errorf("%s match = %v, want %v", rule.String(), got, want[i])
			}
		}
	}
	check([]bool{true, false, false, false, true})
	// Same physical interface and addresses, with a metering/Data Saver change.
	host.setSnapshot(`[{"name":"wlan0","index":4,"mtu":1500,"up":true,"type":"wifi","expensive":true,"constrained":true,"addrs":[{"ip":"192.168.1.5","prefixLen":24}]}]`)
	manager.NetworkChanged()
	check([]bool{true, true, true, false, true})
	// Handover has no DNS configuration dependency and replaces all metadata.
	host.setSnapshot(`[{"name":"rmnet0","index":5,"mtu":1500,"up":true,"type":"cellular","expensive":true,"addrs":[{"ip":"2001:db8::5","prefixLen":64}]}]`)
	manager.NetworkChanged()
	check([]bool{false, true, false, true, false})
	host.setSnapshot(`[]`)
	manager.NetworkChanged()
	check([]bool{false, false, false, false, false})
}
