// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestManagedConfigReservesTunnelAndDNS(t *testing.T) {
	input := `{
		"log":{"level":"debug"},
		"outbounds":[{"type":"direct","tag":"direct"}],
		"route":{"rules":[{"domain":"example.com","outbound":"direct"}],"final":"direct"},
		"dns":{"servers":[{"type":"udp","tag":"public","server":"1.1.1.1"}],"final":"public"}
	}`

	managed, err := managedConfig(input)
	if err != nil {
		t.Fatalf("managedConfig() error = %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(managed, &config); err != nil {
		t.Fatalf("unmarshal managed config: %v", err)
	}

	logOptions := config["log"].(map[string]any)
	if logOptions["disabled"] != true {
		t.Errorf("log.disabled = %v, want true", logOptions["disabled"])
	}
	inbounds := config["inbounds"].([]any)
	if len(inbounds) != 1 || inbounds[0].(map[string]any)["type"] != "tun" {
		t.Errorf("managed inbounds = %#v, want exactly the internal TUN", inbounds)
	}
	route := config["route"].(map[string]any)
	rules := route["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("route.rules count = %d, want injected DNS rule and user rule", len(rules))
	}
	firstRouteRule := rules[0].(map[string]any)
	if firstRouteRule["action"] != "hijack-dns" || firstRouteRule["port"] != float64(53) {
		t.Errorf("first route rule = %#v, want mandatory DNS hijack", firstRouteRule)
	}
	if route["final"] != "direct" {
		t.Errorf("route.final = %v, want the user's final outbound", route["final"])
	}
	if route["auto_detect_interface"] != true {
		t.Errorf("route.auto_detect_interface = %v, want Android-managed transport protection enabled", route["auto_detect_interface"])
	}
	dns := config["dns"].(map[string]any)
	servers := dns["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("dns.servers count = %d, want native transport plus user server", len(servers))
	}
	if first := servers[0].(map[string]any); first["type"] != nativeDNS || first["tag"] != nativeDNSTag {
		t.Errorf("first DNS server = %#v, want the reserved Tailscale resolver", first)
	}
	dnsRules := dns["rules"].([]any)
	if len(dnsRules) == 0 {
		t.Fatal("missing mandatory Tailscale DNS rule")
	}
	firstDNSRule := dnsRules[0].(map[string]any)
	if firstDNSRule["server"] != nativeDNSTag {
		t.Errorf("first DNS rule = %#v, want native resolver", firstDNSRule)
	}
	if dns["reverse_mapping"] != true {
		t.Errorf("dns.reverse_mapping = %v, want true", dns["reverse_mapping"])
	}
}

func TestManagedConfigRejectsAndroidOwnedOptions(t *testing.T) {
	tests := []struct {
		name string
		json string
		want string
	}{
		{"second inbound", `{"inbounds":[],"route":{"final":"direct"}}`, "inbounds"},
		{"second tailscale endpoint", `{"endpoints":[],"route":{"final":"direct"}}`, "endpoints"},
		{"services", `{"services":[],"route":{"final":"direct"}}`, "services"},
		{"network namespaces", `{"network_namespaces":[],"route":{"final":"direct"}}`, "network_namespaces"},
		{"file logging", `{"log":{"output":"/tmp/sing-box.log"},"route":{"final":"direct"}}`, "log.output"},
		{"automatic route management", `{"route":{"auto_detect_interface":true,"final":"direct"}}`, "route.auto_detect_interface"},
		{"missing final outbound", `{"route":{"rules":[]}}`, "route.final"},
		{"reserved DNS tag", `{"dns":{"servers":[{"type":"udp","tag":"__tailscale_dns","server":"1.1.1.1"}]},"route":{"final":"direct"}}`, "reserved DNS tag"},
		{"wrong rules shape", `{"route":{"rules":{},"final":"direct"}}`, "rules"},
		{"outbound bind interface", `{"outbounds":[{"type":"direct","tag":"direct","bind_interface":"wlan0"}],"route":{"final":"direct"}}`, "bind_interface"},
		{"outbound socket address", `{"outbounds":[{"type":"direct","tag":"direct","inet4_bind_address":"192.0.2.1"}],"route":{"final":"direct"}}`, "inet4_bind_address"},
		{"outbound routing mark", `{"outbounds":[{"type":"direct","tag":"direct","routing_mark":1}],"route":{"final":"direct"}}`, "routing_mark"},
		{"outbound network strategy", `{"outbounds":[{"type":"direct","tag":"direct","network_strategy":"default"}],"route":{"final":"direct"}}`, "network_strategy"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := managedConfig(test.json)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("managedConfig() error = %v, want message containing %q", err, test.want)
			}
		})
	}
}

func TestManagedConfigRejectsInvalidAndOversizedJSON(t *testing.T) {
	for _, input := range []string{"null", "[]", "{", strings.Repeat(" ", (2<<20)+1)} {
		if _, err := managedConfig(input); err == nil {
			t.Errorf("managedConfig(%d bytes) succeeded; want error", len(input))
		}
	}
}

func TestManagedConfigAllowsDNSBeforeRejectingUnknownOwners(t *testing.T) {
	input := `{
		"route":{
			"rules":[{"package_name":"com.example.browser","action":"route","outbound":"proxy"}],
			"final":"direct"
		}
	}`
	managed, err := managedConfig(input)
	if err != nil {
		t.Fatalf("managedConfig() error = %v", err)
	}
	var config map[string]any
	if err := json.Unmarshal(managed, &config); err != nil {
		t.Fatalf("unmarshal managed config: %v", err)
	}
	rules := config["route"].(map[string]any)["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("route.rules count = %d, want DNS rule, unknown-owner guard, and user rule", len(rules))
	}
	dnsRule := rules[0].(map[string]any)
	if dnsRule["action"] != "hijack-dns" {
		t.Errorf("DNS rule = %#v, want mandatory DNS hijack before owner lookup", dnsRule)
	}
	guard := rules[1].(map[string]any)
	if guard["action"] != "reject" || guard["invert"] != true {
		t.Errorf("owner guard = %#v, want reject for flows without a resolved package owner", guard)
	}
	if patterns, ok := guard["package_name_regex"].([]any); !ok || len(patterns) != 1 || patterns[0] != ".+" {
		t.Errorf("owner guard package patterns = %#v, want any known package", guard["package_name_regex"])
	}
}
