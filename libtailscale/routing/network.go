// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"encoding/json"
	"net/netip"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/control"
	"github.com/tailscale/tailscale-android/libtailscale/ifaceparse"
)

// ParseNetworkInterfacesJSON reads the Android interface snapshot used by both
// Tailscale and sing-box. Network conditions must describe physical networks,
// not the VPN interface carrying intercepted packets.
func ParseNetworkInterfacesJSON(payload []byte) ([]adapter.NetworkInterface, error) {
	parsed, _, err := ifaceparse.ParseInterfacesJSONAsNetmon(payload)
	if err != nil {
		return nil, err
	}
	if len(parsed) == 0 {
		return nil, nil
	}
	var snapshot []struct {
		Name        string `json:"name"`
		Type        string `json:"type"`
		Expensive   bool   `json:"expensive"`
		Constrained bool   `json:"constrained"`
	}
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return nil, err
	}
	metadata := make(map[string]adapter.NetworkInterface, len(snapshot))
	for _, i := range snapshot {
		typ, ok := C.StringToInterfaceType[i.Type]
		if !ok {
			// The sing-box zero value means Wi-Fi. An unclassified or VPN
			// interface must never acquire that classification by default.
			typ = C.InterfaceTypeOther
		}
		metadata[i.Name] = adapter.NetworkInterface{Type: typ, Expensive: i.Expensive, Constrained: i.Constrained}
	}
	var result []adapter.NetworkInterface
	for _, i := range parsed {
		if i.Interface == nil {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		var prefixes []netip.Prefix
		for _, a := range addrs {
			if p, err := netip.ParsePrefix(a.String()); err == nil {
				prefixes = append(prefixes, p)
			}
		}
		network := metadata[i.Name]
		network.Interface = control.InterfaceFromNetAddrs(*i.Interface, prefixes)
		result = append(result, network)
	}
	return result, nil
}
