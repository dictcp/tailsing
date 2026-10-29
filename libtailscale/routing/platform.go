// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/x/list"
)

// Host binds the engine to the existing Android service and Tailscale identity.
type Host interface {
	Protect(fd int) error
	DefaultInterface() *control.Interface
	Interfaces() ([]adapter.NetworkInterface, error)
	FindOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error)
	DialTailnet(context.Context, string, netip.AddrPort) (net.Conn, error)
	ListenTailnet(context.Context, netip.AddrPort) (net.PacketConn, error)
	QueryDNS(context.Context, []byte) ([]byte, error)
	DNSDomains() []string
}

// Unused optional platform facilities return explicit errors rather than
// delegating to a second VPN client or opening listeners from imported JSON.
type platform struct {
	host      Host
	port      *packetPort
	monitor   *interfaceMonitor
	addresses []netip.Addr
}

func (p *platform) Initialize(network adapter.NetworkManager) error {
	p.monitor.network = network
	return network.UpdateInterfaces()
}
func (p *platform) UsePlatformAutoDetectInterfaceControl() bool { return true }
func (p *platform) AutoDetectInterfaceControl(fd int) error     { return p.host.Protect(fd) }
func (p *platform) UsePlatformInterface() bool                  { return true }
func (p *platform) OpenInterface(o *tun.Options, _ option.TunPlatformOptions) (tun.Tun, error) {
	for _, a := range o.Inet4Address {
		p.addresses = append(p.addresses, a.Addr())
	}
	for _, a := range o.Inet6Address {
		p.addresses = append(p.addresses, a.Addr())
	}
	return p.port, nil
}
func (p *platform) ProcessPlatformOptions(option.TunPlatformOptions) error { return nil }
func (p *platform) UsePlatformDefaultInterfaceMonitor() bool               { return true }
func (p *platform) CreateDefaultInterfaceMonitor(logger.Logger) tun.DefaultInterfaceMonitor {
	return p.monitor
}
func (p *platform) UsePlatformNetworkInterfaces() bool { return true }
func (p *platform) NetworkInterfaces() ([]adapter.NetworkInterface, error) {
	return p.host.Interfaces()
}
func (p *platform) UnderNetworkExtension() bool              { return false }
func (p *platform) NetworkExtensionIncludeAllNetworks() bool { return false }
func (p *platform) ClearDNSCache()                           {}
func (p *platform) RequestPermissionForWIFIState() error {
	return errors.New("Wi-Fi SSID rules are not supported in this build")
}
func (p *platform) ReadWIFIState(context.Context) adapter.WIFIState { return adapter.WIFIState{} }
func (p *platform) UsePlatformConnectionOwnerFinder() bool          { return true }
func (p *platform) FindConnectionOwner(r *adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return p.host.FindOwner(r)
}
func (p *platform) UsePlatformWIFIMonitor() bool  { return false }
func (p *platform) UsePlatformNotification() bool { return false }
func (p *platform) SendNotification(*adapter.Notification) error {
	return errors.New("notifications unsupported")
}
func (p *platform) CancelNotification(string, int32) error { return nil }
func (p *platform) MyInterfaceAddress() []netip.Addr {
	// sing-box can start before Android recreates the real VPN interface.
	// Its interface finder then contains only physical addresses, while app
	// packets use the Tailscale addresses assigned to the later VPN. Consult
	// the current platform snapshot so that those local sources reach the
	// Android connection-owner lookup instead of the unknown-owner guard.
	addresses := append([]netip.Addr(nil), p.addresses...)
	interfaces, err := p.host.Interfaces()
	if err != nil {
		return addresses
	}
	seen := make(map[netip.Addr]bool, len(addresses))
	for _, address := range addresses {
		seen[address] = true
	}
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			address := prefix.Addr().Unmap()
			if address.IsValid() && !seen[address] {
				addresses = append(addresses, address)
				seen[address] = true
			}
		}
	}
	return addresses
}
func (p *platform) UsePlatformNeighborResolver() bool { return false }
func (p *platform) StartNeighborMonitor(adapter.NeighborUpdateListener) error {
	return errors.New("neighbor rules unsupported")
}
func (p *platform) CloseNeighborMonitor(adapter.NeighborUpdateListener) error { return nil }
func (p *platform) UsePlatformShell() bool                                    { return false }
func (p *platform) CheckPlatformShell() error                                 { return errors.New("shell unsupported") }
func (p *platform) OpenShellSession(*adapter.PlatformUser, string, []string, string, int32, int32) (adapter.ShellSession, error) {
	return nil, errors.New("shell unsupported")
}
func (p *platform) LookupUser(string) (*adapter.PlatformUser, error) {
	return nil, errors.New("shell unsupported")
}
func (p *platform) LookupSFTPServer() (string, error) { return "", errors.New("shell unsupported") }
func (p *platform) ReadSystemSSHHostKey() ([]byte, error) {
	return nil, errors.New("shell unsupported")
}
func (p *platform) TailscaleHostname() string { return "" }
func (p *platform) UsePlatformBridge() bool   { return false }
func (p *platform) CreateBridge(adapter.BridgeOptions) (adapter.BridgeSession, error) {
	return nil, errors.New("bridge unsupported")
}

type interfaceMonitor struct {
	host      Host
	network   adapter.NetworkManager
	mu        sync.Mutex
	callbacks list.List[tun.DefaultInterfaceUpdateCallback]
	names     []string
}

func (m *interfaceMonitor) Start() error                         { return nil }
func (m *interfaceMonitor) Close() error                         { return nil }
func (m *interfaceMonitor) DefaultInterface() *control.Interface { return m.host.DefaultInterface() }
func (m *interfaceMonitor) OverrideAndroidVPN() bool             { return false }
func (m *interfaceMonitor) AndroidVPNEnabled() bool              { return false }
func (m *interfaceMonitor) RegisterCallback(cb tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callbacks.PushBack(cb)
}
func (m *interfaceMonitor) UnregisterCallback(e *list.Element[tun.DefaultInterfaceUpdateCallback]) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callbacks.Remove(e)
}
func (m *interfaceMonitor) RegisterMyInterface(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.names = append(m.names, s)
}
func (m *interfaceMonitor) MyInterfaces() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.names...)
}
func (m *interfaceMonitor) notify() {
	if m.network != nil {
		if err := m.network.UpdateInterfaces(); err != nil {
			return
		}
	}
	m.mu.Lock()
	var callbacks []tun.DefaultInterfaceUpdateCallback
	for e := m.callbacks.Front(); e != nil; e = e.Next() {
		callbacks = append(callbacks, e.Value)
	}
	m.mu.Unlock()
	for _, cb := range callbacks {
		cb(m.DefaultInterface(), 0)
	}
}
