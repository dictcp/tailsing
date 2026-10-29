// SPDX-License-Identifier: GPL-3.0-or-later
package libtailscale

import "sync"

// Network changes also carry routing metadata updates, even without DNS changes.
var onDNSConfigChanged = make(chan string, 1)
var networkChangeMu sync.Mutex

// OnDNSConfigChanged receives the physical interface from Android LinkProperties.
// An empty name means that no physical network is available.
func OnDNSConfigChanged(ifname string) {
	networkChangeMu.Lock()
	defer networkChangeMu.Unlock()
	// Coalesce pending changes to the latest state. Dropping the new event
	// can otherwise leave routing on a lost interface after a callback burst.
	select {
	case <-onDNSConfigChanged:
	default:
	}
	onDNSConfigChanged <- ifname
}
