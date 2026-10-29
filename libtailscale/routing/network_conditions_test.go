// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManagerValidatesNetworkConditions(t *testing.T) {
	manager := NewManager(&testHost{}, NewDispatcher())
	for _, test := range []struct{ name, rule string }{
		{"wifi", `{"network_type":"wifi","action":"reject"}`},
		{"cellular", `{"network_type":["cellular"],"action":"reject"}`},
		{"logical", `{"type":"logical","mode":"and","rules":[{"network_type":"wifi"},{"network_is_expensive":true}],"action":"reject"}`},
		{"expensive", `{"network_is_expensive":true,"action":"reject"}`},
		{"constrained", `{"network_is_constrained":true,"action":"reject"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := fmt.Sprintf(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[%s],"final":"direct"}}`, test.rule)
			if err := manager.Validate(config); err != nil {
				t.Fatalf("Validate(network condition): %v", err)
			}
		})
	}
	if err := manager.Validate(`{"outbounds":[{"type":"direct","tag":"direct"}],"dns":{"rules":[{"network_type":"wifi","action":"reject"}]},"route":{"final":"direct"}}`); err != nil {
		t.Fatalf("Validate(DNS network condition): %v", err)
	}
	if err := manager.Validate(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rule_set":[{"type":"inline","tag":"wifi","rules":[{"network_type":"wifi"}]}],"rules":[{"rule_set":"wifi","action":"reject"}],"final":"direct"}}`); err != nil {
		t.Fatalf("Validate(inline rule-set network condition): %v", err)
	}
}

func TestManagerRejectsWiFiIdentityInLocalRuleSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wifi.json")
	if err := os.WriteFile(path, []byte(`{"version":4,"rules":[{"wifi_ssid":"example"}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	manager := NewManager(&testHost{}, NewDispatcher())
	config := fmt.Sprintf(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","rule_set":[{"type":"local","tag":"wifi","format":"source","path":%q}],"rules":[{"rule_set":"wifi","action":"reject"}]}}`, path)
	if err := manager.Validate(config); err == nil || !strings.Contains(err.Error(), "Wi-Fi identity") {
		t.Fatalf("Validate(local Wi-Fi rule set) = %v, want explicit unsupported Wi-Fi identity error", err)
	}
}

func TestManagerBlocksRemoteWiFiIdentityRuleSet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":4,"rules":[{"wifi_bssid":"00:11:22:33:44:55"}]}`))
	}))
	defer server.Close()
	dispatcher := NewDispatcher()
	manager := NewManager(loopbackTestHost(t), dispatcher)
	t.Cleanup(func() { _ = manager.Disable() })
	config := fmt.Sprintf(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct","rule_set":[{"type":"remote","tag":"wifi","format":"source","url":%q}],"rules":[{"rule_set":"wifi","action":"reject"}]}}`, server.URL)
	if err := manager.Apply(config); err == nil || !strings.Contains(err.Error(), "Wi-Fi identity") {
		t.Fatalf("Apply(remote Wi-Fi rule set) = %v, want explicit unsupported Wi-Fi identity error", err)
	}
	if !manager.Enabled() || dispatcher.port.Load() != nil {
		t.Fatal("unsupported remote Wi-Fi identity condition must leave capture blocked")
	}
}

func TestManagedConfigRejectsSocketNetworkSelection(t *testing.T) {
	for _, config := range []string{
		`{"outbounds":[{"type":"direct","network_type":"wifi"}],"route":{"final":"direct"}}`,
		`{"dns":{"servers":[{"type":"udp","server":"1.1.1.1","network_type":"wifi"}]},"route":{"final":"direct"}}`,
		`{"outbounds":[{"type":"direct","tls":{"network_type":"wifi"}}],"route":{"final":"direct"}}`,
		`{"route":{"rules":[{"network_type":"wifi","network_strategy":"default","action":"reject"}],"final":"direct"}}`,
		`{"route":{"rules":[{"type":"logical","mode":"or","rules":[{"network_type":"wifi","bind_interface":"wlan0"}],"action":"reject"}],"final":"direct"}}`,
		`{"route":{"rules":[{"domain":"example.com","tls":{"network_type":"wifi"}}],"final":"direct"}}`,
	} {
		if _, err := managedConfig(config); err == nil || !strings.Contains(err.Error(), "socket protection") {
			t.Errorf("managedConfig(%s) = %v, want Android socket protection error", config, err)
		}
	}
}

func TestManagedConfigRejectsUnsupportedWiFiIdentity(t *testing.T) {
	for _, condition := range []string{"wifi_ssid", "wifi_bssid"} {
		for _, section := range []string{"route", "dns"} {
			config := fmt.Sprintf(`{%q:{"rules":[{"type":"logical","mode":"and","rules":[{%q:"example"}],"action":"reject"}],"final":"direct"}}`, section, condition)
			if section == "dns" {
				config = strings.TrimSuffix(config, "}") + `,"route":{"final":"direct"}}`
			}
			if _, err := managedConfig(config); err == nil || !strings.Contains(err.Error(), condition) || !strings.Contains(err.Error(), "unsupported") {
				t.Errorf("managedConfig(%s) = %v, want explicit unsupported %s error", section, err, condition)
			}
		}
		inline := fmt.Sprintf(`{"route":{"final":"direct","rule_set":[{"type":"inline","tag":"wifi","rules":[{%q:"example"}]}]}}`, condition)
		if _, err := managedConfig(inline); err == nil || !strings.Contains(err.Error(), "unsupported") {
			t.Errorf("managedConfig(inline %s) = %v, want unsupported Wi-Fi condition", condition, err)
		}
	}
}
