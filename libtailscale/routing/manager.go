// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

const Sample = `{
  "log": {"disabled": true},
  "dns": {
    "servers": [{"type": "udp", "tag": "public", "server": "1.1.1.1"}],
    "final": "public",
    "reverse_mapping": true
  },
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {"type": "socks", "tag": "proxy", "server": "127.0.0.1", "server_port": 1080, "version": "5"},
    {"type": "tailscale-exit", "tag": "exit"}
  ],
  "route": {
    "default_domain_resolver": "public",
    "rules": [{"action": "sniff"}],
    "final": "direct"
  }
}`

type Manager struct {
	mu         sync.Mutex
	host       Host
	dispatcher *Dispatcher
	box        *box.Box
	platform   *platform
	status     string
	lastConfig string
}

func NewManager(host Host, dispatcher *Dispatcher) *Manager {
	return &Manager{host: host, dispatcher: dispatcher, status: "Disabled"}
}
func (m *Manager) Status() string { m.mu.Lock(); defer m.mu.Unlock(); return m.status }
func (m *Manager) Enabled() bool  { return m.dispatcher.enabled.Load() }

func (m *Manager) create(raw string) (*box.Box, *platform, error) {
	config, err := managedConfig(raw)
	if err != nil {
		return nil, nil, err
	}
	inbounds := include.InboundRegistry()
	outbounds := include.OutboundRegistry()
	dnsRegistry := include.DNSTransportRegistry()
	registerNative(outbounds, dnsRegistry, m.host)
	ctx := box.Context(context.Background(), inbounds, outbounds, include.EndpointRegistry(), dnsRegistry, include.ServiceRegistry(), include.CertificateProviderRegistry())
	p := &platform{host: m.host, port: m.dispatcher.newPort(), monitor: &interfaceMonitor{host: m.host}}
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, p)
	var options option.Options
	if err = sjson.UnmarshalContext(ctx, config, &options); err != nil {
		p.port.Close()
		return nil, nil, fmt.Errorf("configuration: %w", err)
	}
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		p.port.Close()
		return nil, nil, fmt.Errorf("configuration: %w", err)
	}
	validator := networkRuleSetValidator{next: service.FromContext[adapter.DNSRuleSetUpdateValidator](ctx)}
	service.MustRegister[adapter.DNSRuleSetUpdateValidator](ctx, validator)
	// Local and inline rule sets load during box.New; remote sets and future
	// reloads use the metadata validation hook above before publishing rules.
	for _, set := range options.Route.RuleSet {
		for _, tag := range set.Tag {
			if ruleSet, ok := instance.Router().RuleSet(tag); ok {
				if metadata := ruleSet.Metadata(); metadata.ContainsWIFIRule {
					err := validator.ValidateRuleSetMetadataUpdate(tag, metadata)
					instance.Close()
					p.port.Close()
					return nil, nil, fmt.Errorf("configuration: %w", err)
				}
			}
		}
	}
	return instance, p, nil
}
func (m *Manager) Validate(raw string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	instance, p, err := m.create(raw)
	if err != nil {
		return err
	}
	defer p.port.Close()
	return instance.Close()
}
func (m *Manager) Apply(raw string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyLocked(raw)
}
func (m *Manager) applyLocked(raw string) error {
	instance, p, err := m.create(raw)
	if err != nil {
		return err
	}
	m.lastConfig = raw
	// Hold capture while replacing the runtime. A failed replacement blocks
	// Internet packets and cannot silently reactivate a direct path.
	m.dispatcher.SetEnabled(true)
	m.dispatcher.setPort(nil)
	if m.box != nil {
		m.box.Close()
		m.box = nil
	}
	m.platform = nil
	if err = instance.Start(); err != nil {
		instance.Close()
		p.port.Close()
		m.status = "Blocked: routing engine could not start"
		return fmt.Errorf("start routing: %w", err)
	}
	m.box = instance
	m.platform = p
	m.dispatcher.setPort(p.port)
	m.status = "Rules active (failed routes block)"
	return nil
}
func (m *Manager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dispatcher.setPort(nil)
	if m.box != nil {
		if err := m.box.Close(); err != nil {
			return err
		}
		m.box = nil
	}
	m.platform = nil
	m.dispatcher.SetEnabled(false)
	m.status = "Disabled"
	return nil
}
func (m *Manager) NetworkChanged() {
	m.mu.Lock()
	p := m.platform
	m.mu.Unlock()
	if p != nil {
		p.monitor.notify()
	}
}

// Suspend retains capture and drops Internet traffic while identity or VPN
// capture is unavailable. Recovery only restarts a previously valid profile.
func (m *Manager) Suspend(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dispatcher.SetEnabled(true)
	m.dispatcher.setPort(nil)
	if m.box != nil {
		m.box.Close()
		m.box = nil
	}
	m.platform = nil
	m.status = "Blocked: " + reason
}
func (m *Manager) Resume() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.box != nil {
		return nil
	}
	raw := m.lastConfig
	if raw == "" {
		return errors.New("no valid routing profile available")
	}
	return m.applyLocked(raw)
}

func (m *Manager) CaptureLost() {
	m.Suspend("VPN disconnected")
	m.mu.Lock()
	m.status = "Inactive: Android VPN disconnected; capture unavailable"
	m.mu.Unlock()
}

// managedConfig reserves tunnel ownership while leaving rules and outbounds
// in native sing-box JSON. No imported service can create a second listener.
func managedConfig(raw string) ([]byte, error) {
	if len(raw) > 2<<20 {
		return nil, errors.New("configuration exceeds 2 MiB")
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(raw), &root); err != nil {
		return nil, fmt.Errorf("JSON: %w", err)
	}
	if root == nil {
		return nil, errors.New("configuration must be a JSON object")
	}
	if err := rejectSocketOverrides(root); err != nil {
		return nil, err
	}
	for _, key := range []string{"inbounds", "endpoints", "services", "network_namespaces", "certificate_providers", "experimental", "ntp"} {
		if value, ok := root[key]; ok && value != nil {
			return nil, fmt.Errorf("%s is managed or unsupported in this Android integration", key)
		}
	}
	if value, ok := root["log"]; ok {
		if logOptions, ok := value.(map[string]any); !ok {
			return nil, errors.New("log must be an object")
		} else if logOptions["output"] != nil {
			return nil, errors.New("log.output is unsupported")
		}
	}
	// Keep JSON and connection metadata off remote Tailscale diagnostic logs.
	root["log"] = map[string]any{"disabled": true}
	root["inbounds"] = []any{map[string]any{"type": "tun", "tag": "__android", "address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "mtu": 1280, "stack": "gvisor", "auto_route": false}}
	route, ok := root["route"].(map[string]any)
	if !ok {
		if root["route"] != nil {
			return nil, errors.New("route must be an object")
		}
		route = map[string]any{}
		root["route"] = route
	}
	for _, key := range []string{"auto_detect_interface", "override_android_vpn", "default_interface", "default_mark", "default_network_strategy", "default_network_type", "default_fallback_network_type"} {
		if _, ok := route[key]; ok {
			return nil, fmt.Errorf("route.%s is managed by Android", key)
		}
	}
	route["auto_detect_interface"] = true
	rules, err := arrayValue(route, "rules")
	if err != nil {
		return nil, err
	}
	mandatoryRules := []any{map[string]any{"port": 53, "action": "hijack-dns"}}
	if needsOwner(root) {
		mandatoryRules = append(mandatoryRules, map[string]any{"package_name_regex": []string{".+"}, "invert": true, "action": "reject"})
	}
	route["rules"] = append(mandatoryRules, rules...)
	if _, ok := route["final"]; !ok {
		return nil, errors.New("route.final must explicitly name an outbound")
	}
	dnsOptions, ok := root["dns"].(map[string]any)
	if !ok {
		if root["dns"] != nil {
			return nil, errors.New("dns must be an object")
		}
		dnsOptions = map[string]any{}
		root["dns"] = dnsOptions
	}
	servers, err := arrayValue(dnsOptions, "servers")
	if err != nil {
		return nil, err
	}
	for _, server := range servers {
		if entry, ok := server.(map[string]any); ok && entry["tag"] == nativeDNSTag {
			return nil, errors.New("reserved DNS tag: " + nativeDNSTag)
		}
	}
	dnsOptions["servers"] = append([]any{map[string]any{"type": nativeDNS, "tag": nativeDNSTag}}, servers...)
	dnsRules, err := arrayValue(dnsOptions, "rules")
	if err != nil {
		return nil, err
	}
	dnsOptions["rules"] = append([]any{map[string]any{"preferred_by": []string{nativeDNSTag}, "server": nativeDNSTag}}, dnsRules...)
	if _, ok := dnsOptions["final"]; !ok {
		dnsOptions["final"] = nativeDNSTag
	}
	dnsOptions["reverse_mapping"] = true
	return json.Marshal(root)
}
func arrayValue(root map[string]any, key string) ([]any, error) {
	value, ok := root[key]
	if !ok || value == nil {
		return nil, nil
	}
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", key)
	}
	return array, nil
}

func needsOwner(value any) bool {
	switch v := value.(type) {
	case map[string]any:
		for key, entry := range v {
			switch key {
			case "package_name", "package_name_regex", "process_name", "process_path", "process_path_regex", "user_id", "user":
				return true
			}
			if needsOwner(entry) {
				return true
			}
		}
	case []any:
		for _, entry := range v {
			if needsOwner(entry) {
				return true
			}
		}
	}
	return false
}

func rejectSocketOverrides(value any) error {
	return rejectManagedNetworkOptions(value, networkConfigRoot)
}

type networkConfigContext uint8

const (
	networkConfigOther networkConfigContext = iota
	networkConfigRoot
	networkConfigSection
	networkConfigRuleSets
	networkConfigRuleSet
	networkConfigRules
	networkConfigRule
)

func rejectManagedNetworkOptions(value any, context networkConfigContext) error {
	switch v := value.(type) {
	case map[string]any:
		for key, entry := range v {
			switch key {
			case "wifi_ssid", "wifi_bssid":
				return fmt.Errorf("%s is unsupported: Wi-Fi identity permissions and monitoring are unavailable in this Android integration", key)
			case "bind_interface", "inet4_bind_address", "inet6_bind_address", "routing_mark", "network_strategy", "fallback_network_type":
				return fmt.Errorf("%s is managed by Android socket protection", key)
			case "network_type":
				// This key is both a rule condition and a dialer option. Only
				// condition objects may use it; all dialers remain Android-bound.
				if context != networkConfigRule {
					return fmt.Errorf("%s is managed by Android socket protection", key)
				}
			}
			childContext := networkConfigOther
			switch {
			case context == networkConfigRoot && (key == "route" || key == "dns"):
				childContext = networkConfigSection
			case context == networkConfigSection && key == "rules":
				childContext = networkConfigRules
			case context == networkConfigSection && key == "rule_set":
				childContext = networkConfigRuleSets
			case context == networkConfigRuleSet && v["type"] == "inline" && key == "rules":
				childContext = networkConfigRules
			case context == networkConfigRule && v["type"] == "logical" && key == "rules":
				childContext = networkConfigRules
			}
			if err := rejectManagedNetworkOptions(entry, childContext); err != nil {
				return err
			}
		}
	case []any:
		childContext := networkConfigOther
		if context == networkConfigRules {
			childContext = networkConfigRule
		} else if context == networkConfigRuleSets {
			childContext = networkConfigRuleSet
		}
		for _, entry := range v {
			if err := rejectManagedNetworkOptions(entry, childContext); err != nil {
				return err
			}
		}
	}
	return nil
}
