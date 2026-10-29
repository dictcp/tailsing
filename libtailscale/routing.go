// SPDX-License-Identifier: GPL-3.0-or-later
package libtailscale

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
	"github.com/tailscale/tailscale-android/libtailscale/routing"
	"tailscale.com/ipn"
)

func (a *App) RoutingConfig() (string, error) {
	raw, err := a.appCtx.DecryptFromPref("singbox-active-config")
	if err != nil {
		return "", err
	}
	if raw == "" {
		return routing.Sample, nil
	}
	return raw, nil
}
func (a *App) RoutingStatus() string { a.ready.Wait(); return a.routingBackend.routing.Status() }
func (a *App) ValidateRoutingConfig(raw string) error {
	a.ready.Wait()
	return a.routingBackend.routing.Validate(raw)
}
func (a *App) ApplyRoutingConfig(raw string) error {
	a.ready.Wait()
	a.routingMu.Lock()
	defer a.routingMu.Unlock()
	b := a.routingBackend
	err := b.routing.Apply(raw)
	if b.routing.Enabled() {
		b.routingEnabled.Store(true)
		if captureErr := a.reconfigureRouting(); captureErr != nil {
			b.routing.Suspend("VPN capture unavailable")
			return fmt.Errorf("VPN capture: %w", captureErr)
		}
	}
	if err != nil {
		return err
	}
	if b.activeService.Load() == nil || b.backend.State() != ipn.Running {
		b.routing.Suspend("connect Tailscale before applying routing")
		return errors.New("routing is blocked; connect Tailscale and apply again")
	}
	return a.appCtx.EncryptToPref("singbox-active-config", raw)
}
func (a *App) DisableRouting() error {
	a.ready.Wait()
	a.routingMu.Lock()
	defer a.routingMu.Unlock()
	b := a.routingBackend
	b.routingEnabled.Store(false)
	if err := a.reconfigureRouting(); err != nil {
		b.routingEnabled.Store(true)
		return err
	}
	if err := b.routing.Disable(); err != nil {
		return err
	}
	return a.appCtx.EncryptToPref("singbox-active-config", "")
}
func (a *App) reconfigureRouting() error {
	reply := make(chan error, 1)
	a.routingChanges <- reply
	return <-reply
}

type routingHost struct{ b *backend }

func (h *routingHost) Protect(fd int) error {
	ref := h.b.activeService.Load()
	if ref == nil {
		return errors.New("VPN service unavailable")
	}
	service := *ref
	if !service.Protect(int32(fd)) {
		return errors.New("Android socket protection failed")
	}
	if !h.b.appCtx.BindSocketToNetwork(int32(fd)) {
		return errors.New("Android physical network binding failed")
	}
	return nil
}
func (h *routingHost) Interfaces() ([]adapter.NetworkInterface, error) {
	raw, err := h.b.appCtx.GetInterfacesAsJson()
	if err != nil {
		return nil, err
	}
	return routing.ParseNetworkInterfacesJSON([]byte(raw))
}
func (h *routingHost) DefaultInterface() *control.Interface {
	if name := h.b.physicalInterface.Load(); name != nil {
		if *name == "" {
			return nil
		}
		if interfaces, err := h.Interfaces(); err == nil {
			for _, i := range interfaces {
				if i.Name == *name {
					value := i.Interface
					return &value
				}
			}
		}
		return nil
	}
	if h.b.netMon == nil {
		return nil
	}
	state := h.b.netMon.InterfaceState()
	if state == nil {
		return nil
	}
	name := state.DefaultRouteInterface
	if i, ok := state.Interface[name]; ok && i.Interface != nil {
		value := control.InterfaceFromNetAddrs(*i.Interface, state.InterfaceIPs[name])
		return &value
	}
	return nil
}
func (h *routingHost) FindOwner(r *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	raw, err := h.b.appCtx.FindConnectionOwnerJSON(r.IpProtocol, r.SourceAddress, r.SourcePort, r.DestinationAddress, r.DestinationPort)
	if err != nil {
		return nil, err
	}
	var owner struct {
		UID      int32    `json:"uid"`
		Packages []string `json:"packages"`
	}
	if err = json.Unmarshal([]byte(raw), &owner); err != nil {
		return nil, err
	}
	if owner.UID < 0 || len(owner.Packages) == 0 {
		return nil, errors.New("connection owner unavailable")
	}
	return &adapter.ConnectionOwner{UserId: owner.UID, AndroidPackageNames: owner.Packages}, nil
}
func (h *routingHost) sourceAddress(remote netip.Addr) (netip.Addr, error) {
	if h.b.backend.State() != ipn.Running {
		return netip.Addr{}, errors.New("Tailscale is not connected")
	}
	prefs := h.b.backend.Prefs()
	if prefs.ExitNodeID() == "" && !prefs.ExitNodeIP().IsValid() {
		return netip.Addr{}, errors.New("no Tailscale exit node selected")
	}
	nm := h.b.backend.NetMap()
	if nm == nil {
		return netip.Addr{}, errors.New("Tailscale network map unavailable")
	}
	for _, p := range nm.GetAddresses().All() {
		if p.Addr().Is4() == remote.Is4() {
			return p.Addr(), nil
		}
	}
	return netip.Addr{}, errors.New("no Tailscale source address for destination family")
}
func (h *routingHost) DialTailnet(ctx context.Context, network string, destination netip.AddrPort) (net.Conn, error) {
	source, err := h.sourceAddress(destination.Addr())
	if err != nil {
		return nil, err
	}
	ns := h.b.nativeNetstack
	switch network {
	case "tcp", "tcp4", "tcp6":
		return ns.DialContextTCPWithBind(ctx, source, destination)
	case "udp", "udp4", "udp6":
		return ns.DialContextUDPWithBind(ctx, source, destination)
	default:
		return nil, errors.New("unsupported Tailscale outbound network")
	}
}
func (h *routingHost) ListenTailnet(ctx context.Context, destination netip.AddrPort) (net.PacketConn, error) {
	source, err := h.sourceAddress(destination.Addr())
	if err != nil {
		return nil, err
	}
	return h.b.nativeNetstack.DialContextUDPWithBind(ctx, source, destination)
}
func (h *routingHost) QueryDNS(ctx context.Context, query []byte) ([]byte, error) {
	nm := h.b.backend.NetMap()
	if nm == nil {
		return nil, errors.New("Tailscale DNS unavailable")
	}
	var source netip.Addr
	for _, p := range nm.GetAddresses().All() {
		if p.Addr().Is4() {
			source = p.Addr()
			break
		}
	}
	if !source.IsValid() {
		return nil, errors.New("Tailscale DNS source unavailable")
	}
	// This bridge carries complete messages in-process. Let the backend retry
	// truncated upstream UDP replies over TCP; sing-box handles client framing.
	return h.b.sys.DNSManager.Get().Query(ctx, query, "tcp", netip.AddrPortFrom(source, 0))
}
func (h *routingHost) DNSDomains() []string {
	nm := h.b.backend.NetMap()
	if nm == nil {
		return nil
	}
	domains := append([]string(nil), nm.DNS.Domains...)
	for suffix := range nm.DNS.Routes {
		suffix = strings.Trim(suffix, ".")
		if suffix != "" {
			domains = append(domains, suffix)
		}
	}
	return domains
}
