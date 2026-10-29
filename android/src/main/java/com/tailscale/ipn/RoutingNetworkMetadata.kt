// SPDX-License-Identifier: GPL-3.0-or-later
package com.tailscale.ipn

import android.net.ConnectivityManager
import android.net.NetworkCapabilities

internal data class RoutingNetworkMetadata(
    val type: String = "other",
    val expensive: Boolean = false,
    val constrained: Boolean = false,
)

internal fun routingMetadataForNetwork(
    capabilities: NetworkCapabilities?,
    restrictBackgroundStatus: Int,
): RoutingNetworkMetadata {
  if (capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) != true) {
    return RoutingNetworkMetadata()
  }
  val type =
      when {
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
        capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        else -> "other"
      }
  val metered = !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
  // Android Data Saver restricts this app on metered networks. Unmetered
  // networks and apps exempted from Data Saver are not constrained.
  val constrained =
      metered && restrictBackgroundStatus == ConnectivityManager.RESTRICT_BACKGROUND_STATUS_ENABLED
  return RoutingNetworkMetadata(type, metered, constrained)
}
