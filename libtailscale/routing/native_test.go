// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestNativeDNSPrefersTailnetPrivateNames(t *testing.T) {
	host := &testHost{dnsNames: []string{"example-tailnet.ts.net"}}
	transport := &nativeTransport{host: host}
	tests := []struct {
		name string
		want bool
	}{
		{"short device name", true},
		{"tailnet root", true},
		{"tailnet subdomain", true},
		{"IPv4 reverse", true},
		{"IPv6 reverse", true},
		{"public domain", false},
		{"suffix lookalike", false},
	}
	queries := []string{
		"nas",
		"example-tailnet.ts.net",
		"router.example-tailnet.ts.net",
		"4.3.2.100.in-addr.arpa",
		"host.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa",
		"example.com",
		"notexample-tailnet.ts.net",
	}
	for i, query := range queries {
		t.Run(tests[i].name, func(t *testing.T) {
			if got := transport.PreferredDomain(query); got != tests[i].want {
				t.Errorf("PreferredDomain(%q) = %v, want %v", query, got, tests[i].want)
			}
		})
	}
}

func TestNativeDNSExchangeUsesTailnetResolver(t *testing.T) {
	query := new(mdns.Msg)
	query.SetQuestion("printer.example-tailnet.ts.net.", mdns.TypeA)
	reply := new(mdns.Msg)
	reply.SetReply(query)
	wireReply, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}
	host := &testHost{dnsNames: []string{"example-tailnet.ts.net"}, dnsReply: wireReply}
	transport := &nativeTransport{host: host}

	response, err := transport.Exchange(context.Background(), query)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if response.Question[0].Name != query.Question[0].Name {
		t.Errorf("response question = %q, want %q", response.Question[0].Name, query.Question[0].Name)
	}
	if got := host.dnsCallCount(); got != 1 {
		t.Errorf("Tailscale DNS calls = %d, want 1", got)
	}

	host.dnsErr = errors.New("private resolver unavailable")
	if _, err := transport.Exchange(context.Background(), query); err == nil {
		t.Fatal("Exchange() succeeded while Tailscale DNS failed")
	}
	if got := host.dnsCallCount(); got != 2 {
		t.Errorf("Tailscale DNS calls after failed lookup = %d, want 2", got)
	}
}

func TestDirectLoopbackOutboundCallsPlatformSocketProtection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.Close()
		}
		accepted <- err
	}()

	host := loopbackTestHost(t)
	inbounds := include.InboundRegistry()
	outbounds := include.OutboundRegistry()
	dnsRegistry := include.DNSTransportRegistry()
	registerNative(outbounds, dnsRegistry, host)
	ctx := box.Context(context.Background(), inbounds, outbounds, include.EndpointRegistry(), dnsRegistry, include.ServiceRegistry(), include.CertificateProviderRegistry())
	platform := &platform{host: host, monitor: &interfaceMonitor{host: host}}
	ctx = service.ContextWith[adapter.PlatformInterface](ctx, platform)
	var options option.Options
	config := []byte(`{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"auto_detect_interface":true,"final":"direct"}}`)
	if err := sjson.UnmarshalContext(ctx, config, &options); err != nil {
		t.Fatalf("parse test config: %v", err)
	}
	instance, err := box.New(box.Options{Options: options, Context: ctx})
	if err != nil {
		t.Fatalf("create sing-box: %v", err)
	}
	defer instance.Close()
	if err := instance.Start(); err != nil {
		t.Fatalf("start sing-box: %v", err)
	}
	direct, ok := instance.Outbound().Outbound("direct")
	if !ok {
		t.Fatal("direct outbound was not registered")
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	var conn net.Conn
	deadline := time.Now().Add(time.Second)
	for {
		conn, err = direct.DialContext(context.Background(), "tcp", M.Socksaddr{Addr: address.Addr(), Port: address.Port()})
		if err == nil {
			break
		}
		// The route network manager refreshes the platform interface list
		// asynchronously after Start. Retry only while that refresh is pending.
		if !strings.Contains(err.Error(), "no available network interface") || time.Now().After(deadline) {
			t.Fatalf("direct loopback outbound dial: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_ = conn.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("accept loopback connection: %v", err)
	}
	if got := host.protectedFDCount(); got == 0 {
		t.Fatal("loopback outbound dial did not call the platform socket-protection callback")
	}
}
