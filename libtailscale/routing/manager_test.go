// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	rangescalc "github.com/tailscale/tailscale-android/libtailscale/ranges_calc"
)

func TestManagerKeepsWorkingRuntimeWhenReplacementIsInvalid(t *testing.T) {
	dispatcher := NewDispatcher()
	dispatcher.SetRoutes([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")})
	manager := NewManager(loopbackTestHost(t), dispatcher)
	validConfig := `{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}`
	if err := manager.Apply(validConfig); err != nil {
		t.Fatalf("Apply(valid config) error = %v", err)
	}
	t.Cleanup(func() { _ = manager.Disable() })
	activePort := dispatcher.port.Load()
	if activePort == nil || !manager.Enabled() {
		t.Fatal("Apply() did not establish an active dispatcher state")
	}
	if got := manager.Status(); got != "Rules active (failed routes block)" {
		t.Fatalf("Status() = %q, want active status", got)
	}

	if err := manager.Apply(`{"inbounds":[],"route":{"final":"direct"}}`); err == nil {
		t.Fatal("Apply() accepted a config that replaces the Android-managed TUN")
	}
	if got := dispatcher.port.Load(); got != activePort {
		t.Fatal("invalid replacement changed the active packet port")
	}
	if !manager.Enabled() || manager.Status() != "Rules active (failed routes block)" {
		t.Fatalf("invalid replacement changed runtime state: enabled=%v status=%q", manager.Enabled(), manager.Status())
	}
	if err := manager.Disable(); err != nil {
		t.Fatalf("Disable() error = %v", err)
	}
	if manager.Enabled() || dispatcher.port.Load() != nil || manager.Status() != "Disabled" {
		t.Fatalf("Disable() left routing active: enabled=%v status=%q", manager.Enabled(), manager.Status())
	}
}

func TestWiFiExcludedPrefixWinsOverCapturedDefaultRoute(t *testing.T) {
	allowed := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	wifi := []netip.Prefix{
		netip.MustParsePrefix("192.168.100.0/22"),
		netip.MustParsePrefix("fd00:1234:5678::/64"),
	}
	v4, v6, err := rangescalc.Calculate(allowed, wifi)
	if err != nil {
		t.Fatalf("Calculate() error = %v", err)
	}
	for _, route := range v4 {
		if route.Contains(netip.MustParseAddr("192.168.100.42")) {
			t.Errorf("VPN included route %s captures the local Wi-Fi address", route)
		}
	}
	for _, route := range v6 {
		if route.Contains(netip.MustParseAddr("fd00:1234:5678::42")) {
			t.Errorf("VPN included route %s captures the local Wi-Fi address", route)
		}
	}
	if !containsPrefixAddress(v4, netip.MustParseAddr("1.1.1.1")) ||
		!containsPrefixAddress(v6, netip.MustParseAddr("2606:4700:4700::1111")) {
		t.Fatal("excluding Wi-Fi removed unrelated Internet traffic from VPN capture")
	}
}

func containsPrefixAddress(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func TestManagerBlocksWhenEngineStartFails(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "test rule set unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	dispatcher := NewDispatcher()
	manager := NewManager(loopbackTestHost(t), dispatcher)
	config := fmt.Sprintf(`{
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{
			"rule_set":[{"type":"remote","tag":"unavailable","format":"source","url":%q}],
			"final":"direct"
		}
	}`, server.URL+"/unavailable.json")
	if err := manager.Apply(config); err == nil {
		t.Fatal("Apply() succeeded despite the remote rule set failing at engine start")
	}
	if !manager.Enabled() {
		t.Fatal("failed engine start disabled capture; routing must remain blocked")
	}
	if port := dispatcher.port.Load(); port != nil {
		t.Fatal("failed engine start left a packet port active")
	}
	if got := manager.Status(); got != "Blocked: routing engine could not start" {
		t.Fatalf("Status() = %q, want blocked status", got)
	}
}
