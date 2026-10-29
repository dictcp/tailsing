// SPDX-License-Identifier: GPL-3.0-or-later
package com.tailscale.ipn

import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever

class RoutingNetworkMetadataTest {
  @Test
  fun reportsPhysicalTransportTypes() {
    for ((transport, expected) in
        listOf(
            NetworkCapabilities.TRANSPORT_WIFI to "wifi",
            NetworkCapabilities.TRANSPORT_CELLULAR to "cellular",
            NetworkCapabilities.TRANSPORT_ETHERNET to "ethernet",
            NetworkCapabilities.TRANSPORT_BLUETOOTH to "other",
        )) {
      val metadata = routingMetadataForNetwork(capabilities(transport), DISABLED)
      assertEquals(expected, metadata.type)
    }
  }

  @Test
  fun meteredWifiIsExpensiveAndDataSaverConstrained() {
    val caps = capabilities(NetworkCapabilities.TRANSPORT_WIFI, metered = true)
    assertEquals(
        RoutingNetworkMetadata("wifi", true, false),
        routingMetadataForNetwork(caps, DISABLED),
    )
    assertEquals(
        RoutingNetworkMetadata("wifi", true, true),
        routingMetadataForNetwork(caps, ENABLED),
    )
  }

  @Test
  fun unmeteredCellularIsNeitherExpensiveNorConstrained() {
    val metadata =
        routingMetadataForNetwork(
            capabilities(NetworkCapabilities.TRANSPORT_CELLULAR, metered = false),
            ENABLED,
        )
    assertEquals("cellular", metadata.type)
    assertFalse(metadata.expensive)
    assertFalse(metadata.constrained)
  }

  @Test
  fun dataSaverExemptionRemovesConstraintButKeepsMetering() {
    val metadata =
        routingMetadataForNetwork(
            capabilities(NetworkCapabilities.TRANSPORT_CELLULAR),
            ConnectivityManager.RESTRICT_BACKGROUND_STATUS_WHITELISTED,
        )
    assertTrue(metadata.expensive)
    assertFalse(metadata.constrained)
  }

  @Test
  fun vpnAndUnavailableCapabilitiesNeverDefaultToWifi() {
    assertEquals(RoutingNetworkMetadata(), routingMetadataForNetwork(null, ENABLED))
    val vpn = capabilities(NetworkCapabilities.TRANSPORT_WIFI)
    whenever(vpn.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)).thenReturn(false)
    assertEquals(RoutingNetworkMetadata(), routingMetadataForNetwork(vpn, ENABLED))
  }

  private fun capabilities(transport: Int, metered: Boolean = true): NetworkCapabilities {
    val caps = mock<NetworkCapabilities>()
    whenever(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)).thenReturn(true)
    whenever(caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED))
        .thenReturn(!metered)
    whenever(caps.hasTransport(transport)).thenReturn(true)
    return caps
  }

  private companion object {
    const val DISABLED = ConnectivityManager.RESTRICT_BACKGROUND_STATUS_DISABLED
    const val ENABLED = ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
  }
}
