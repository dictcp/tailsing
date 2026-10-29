// SPDX-License-Identifier: GPL-3.0-or-later
package libtailscale

import "testing"

func TestNetworkChangesRetainLatestQueuedInterface(t *testing.T) {
	select {
	case <-onDNSConfigChanged:
	default:
	}
	t.Cleanup(func() {
		select {
		case <-onDNSConfigChanged:
		default:
		}
	})
	OnDNSConfigChanged("") // capabilities arrive before LinkProperties
	OnDNSConfigChanged("wlan0")
	select {
	case got := <-onDNSConfigChanged:
		if got != "wlan0" {
			t.Fatalf("queued interface = %q, want latest wlan0", got)
		}
	default:
		t.Fatal("network change notification was lost")
	}
	OnDNSConfigChanged("wlan0")
	OnDNSConfigChanged("") // no network must clear the old physical interface
	if got := <-onDNSConfigChanged; got != "" {
		t.Fatalf("queued interface = %q, want latest no-network state", got)
	}
}
