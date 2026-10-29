// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/control"
)

type testHost struct {
	mu         sync.Mutex
	defaultIF  *control.Interface
	dnsNames   []string
	dnsCalls   int
	dnsReply   []byte
	dnsErr     error
	protectFDs []int
	dialErr    error
	packetErr  error
}

func (h *testHost) Protect(fd int) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.protectFDs = append(h.protectFDs, fd)
	return nil
}
func (h *testHost) DefaultInterface() *control.Interface { return h.defaultIF }
func (h *testHost) Interfaces() ([]adapter.NetworkInterface, error) {
	if h.defaultIF == nil {
		return nil, nil
	}
	return []adapter.NetworkInterface{{Interface: *h.defaultIF}}, nil
}
func (*testHost) FindOwner(*adapter.FindConnectionOwnerRequest) (*adapter.ConnectionOwner, error) {
	return nil, errors.New("owner unavailable")
}
func (h *testHost) DialTailnet(context.Context, string, netip.AddrPort) (net.Conn, error) {
	if h.dialErr != nil {
		return nil, h.dialErr
	}
	return nil, errors.New("unexpected tailnet dial")
}
func (h *testHost) ListenTailnet(context.Context, netip.AddrPort) (net.PacketConn, error) {
	if h.packetErr != nil {
		return nil, h.packetErr
	}
	return nil, errors.New("unexpected tailnet packet listener")
}
func (h *testHost) QueryDNS(_ context.Context, query []byte) ([]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.dnsCalls++
	if h.dnsErr != nil {
		return nil, h.dnsErr
	}
	return append([]byte(nil), h.dnsReply...), nil
}
func (h *testHost) DNSDomains() []string { return append([]string(nil), h.dnsNames...) }

func (h *testHost) dnsCallCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.dnsCalls
}

func (h *testHost) protectedFDCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.protectFDs)
}

func loopbackTestHost(t *testing.T) *testHost {
	t.Helper()
	iface, err := net.InterfaceByName("lo")
	if err != nil {
		t.Fatalf("find loopback interface: %v", err)
	}
	controlInterface, err := control.InterfaceFromNet(*iface)
	if err != nil {
		t.Fatalf("read loopback interface: %v", err)
	}
	return &testHost{defaultIF: &controlInterface}
}
