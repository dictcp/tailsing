// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
)

const nativeType = "tailscale-exit"
const nativeDNS = "tailscale-native"
const nativeDNSTag = "__tailscale_dns"

func registerNative(registry *outbound.Registry, dnsRegistry *dns.TransportRegistry, host Host) {
	outbound.Register[option.StubOptions](registry, nativeType, func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.StubOptions) (adapter.Outbound, error) {
		return &nativeOutbound{Adapter: outbound.NewAdapter(nativeType, tag, []string{"tcp", "udp"}, nil), host: host}, nil
	})
	dns.RegisterTransport[option.StubOptions](dnsRegistry, nativeDNS, func(_ context.Context, _ log.ContextLogger, tag string, _ option.StubOptions) (adapter.DNSTransport, error) {
		return &nativeTransport{TransportAdapter: dns.NewTransportAdapter(nativeDNS, tag, nil), host: host}, nil
	})
}

type nativeOutbound struct {
	outbound.Adapter
	host Host
}

func (o *nativeOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.IsIP() {
		return nil, errors.New("tailscale-exit requires an IP destination; add a resolve action before routing FQDN destinations")
	}
	return o.host.DialTailnet(ctx, network, netip.AddrPortFrom(destination.Addr, destination.Port))
}
func (o *nativeOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.IsIP() {
		return nil, errors.New("tailscale-exit UDP requires resolved IP destination")
	}
	return o.host.ListenTailnet(ctx, netip.AddrPortFrom(destination.Addr, destination.Port))
}

type nativeTransport struct {
	dns.TransportAdapter
	host Host
}

func (*nativeTransport) Start(adapter.StartStage, *adapter.Scope) error { return nil }
func (*nativeTransport) Reset()                                         {}
func (t *nativeTransport) PreferredDomain(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	// Single-label names and tailnet reverse zones stay private even before a
	// fresh network map arrives after account switches.
	if !strings.Contains(domain, ".") {
		return true
	}
	for _, suffix := range append(t.host.DNSDomains(), "100.in-addr.arpa", "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa") {
		suffix = strings.Trim(strings.ToLower(suffix), ".")
		if suffix != "" && (domain == suffix || strings.HasSuffix(domain, "."+suffix)) {
			return true
		}
	}
	return false
}
func (t *nativeTransport) Exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error) {
	wire, err := message.Pack()
	if err != nil {
		return nil, err
	}
	response, err := t.host.QueryDNS(ctx, wire)
	if err != nil {
		return nil, err
	}
	var result mdns.Msg
	if err = result.Unpack(response); err != nil {
		return nil, err
	}
	return &result, nil
}
func (t *nativeTransport) ExchangeAsync(ctx context.Context, message *mdns.Msg, callback func(*mdns.Msg, error)) {
	go func() { result, err := t.Exchange(ctx, message); callback(result, err) }()
}
