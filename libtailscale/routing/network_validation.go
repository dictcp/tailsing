// SPDX-License-Identifier: GPL-3.0-or-later
package routing

import (
	"fmt"

	"github.com/sagernet/sing-box/adapter"
)

// Rule sets loaded from files or URLs bypass the raw configuration walk.
// Validate their metadata before the engine publishes initial or updated rules,
// retaining the existing rules when a remote update becomes unsupported.
type networkRuleSetValidator struct {
	next adapter.DNSRuleSetUpdateValidator
}

func (v networkRuleSetValidator) ValidateRuleSetMetadataUpdate(tag string, metadata adapter.RuleSetMetadata) error {
	if metadata.ContainsWIFIRule {
		return fmt.Errorf("rule-set %q: Wi-Fi identity conditions (wifi_ssid/wifi_bssid) are unsupported in this Android integration", tag)
	}
	return v.next.ValidateRuleSetMetadataUpdate(tag, metadata)
}
