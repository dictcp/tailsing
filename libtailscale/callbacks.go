// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package libtailscale

import (
	"sync"

	"tailscale.com/net/netmon"
)

var (
	// onVPNRequested receives global IPNService references when
	// a VPN connection is requested.
	onVPNRequested = make(chan IPNService)
	// onDisconnect receives global IPNService references when
	// disconnecting.
	onDisconnect = make(chan IPNService)

	// onGoogleToken receives google ID tokens.
	onGoogleToken = make(chan string)

	// onLog receives Android logs to be sent to the logger
	onLog = make(chan string, 10)

	// onShareFileHelper receives ShareFileHelper references when the app is initialized so that files can be received via Storage Access Framework
	onShareFileHelper = make(chan ShareFileHelper, 1)
)

// OnGatewayChanged is called when LinkProperties provides an updated default gateway IP.
func OnGatewayChanged(gatewayIP string) {
	netmon.UpdateLastKnownDefaultGateway(gatewayIP)
}

var android struct {
	// mu protects all fields of this structure. However, once a
	// non-nil jvm is returned from javaVM, all the other fields may
	// be accessed unlocked.
	mu sync.Mutex

	// appCtx is the global Android App context.
	appCtx AppContext
}
