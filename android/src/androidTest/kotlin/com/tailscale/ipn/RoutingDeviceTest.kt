// SPDX-License-Identifier: GPL-3.0-or-later
package com.tailscale.ipn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Process
import android.os.SystemClock
import android.system.OsConstants
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URI
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import libtailscale.Application
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Device probes run inside the experimental app's UID. The HTTP tests require a separately verified
 * physical-network baseline and a reachable local echo fixture. They do not configure, enable,
 * disable, or replace the user's routing profile.
 *
 * Example runner arguments: -e probeUrl http://example.com/ -e echoUrl
 * http://<reachable-fixture-address>:<port>/echo -e directBaselineConfirmed true
 *
 * The positive probe verifies that this app's own sockets use the active VPN profile. It does not
 * test a second app's UID/package rules.
 */
@RunWith(AndroidJUnit4::class)
class RoutingDeviceTest {
  private val instrumentation = InstrumentationRegistry.getInstrumentation()
  private val context: Context
    get() = instrumentation.targetContext

  private lateinit var app: Application

  @Before
  fun openMainApp() {
    context.startActivity(
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
    )
    instrumentation.waitForIdleSync()
    app = App.get().getLibtailscaleApp()
  }

  @Test
  fun nativeConfigValidationDoesNotChangeTheSavedProfile() {
    val savedBefore = app.routingConfig()

    app.validateRoutingConfig(ApplicationSample.configuration)

    val malformed = runCatching { app.validateRoutingConfig("{") }
    assertTrue("Malformed JSON should be rejected", malformed.isFailure)

    val forbiddenInbound = runCatching {
      app.validateRoutingConfig(
          """{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}""",
      )
    }
    assertTrue("A user-supplied TUN inbound should be rejected", forbiddenInbound.isFailure)
    // Do not let a failed assertion print the user's profile or credentials.
    assertTrue(
        "Validation must leave the saved profile unchanged",
        savedBefore == app.routingConfig(),
    )
  }

  @Test
  fun directHttpBaselineRespondsWhileRoutingIsDisabled() {
    requireActiveVpn()
    assertEquals("Disable routing before checking the direct path", "Disabled", app.routingStatus())
    val status = request(probeUrl(), "GET", ByteArray(0)).status
    assertTrue("Direct HTTP probe did not receive an HTTP response", status in 100..599)
  }

  @Test
  fun httpEchoUsesTheActiveVpn() {
    requireProbePrerequisites()
    val endpoint = echoUrl()
    val payload = "tailscale-singbox-device-probe".toByteArray(StandardCharsets.UTF_8)

    val response = request(endpoint, "POST", payload)
    assertEquals("Echo endpoint should return HTTP 200", 200, response.status)
    assertArrayEquals("Echo endpoint should return the probe payload", payload, response.body)
  }

  @Test
  fun rulesHttpProbeResponds() {
    requireProbePrerequisites()
    val endpoint = numericProbeUrl()
    val status = request(endpoint, "GET", ByteArray(0)).status
    assertTrue("HTTP GET through the active routing profile did not respond.", status in 100..599)
    instrumentation.sendStatus(0, Bundle().apply { putInt("rulesHttpStatus", status) })
  }

  @Test
  fun sourceIpHttpProbe() {
    ensureAuthorizedVpn()
    requireExpectedRoutingMode()
    val endpoint = sourceIpUrl()
    val hostHeader = optionalSourceIpHost()
    val response =
        try {
          request(endpoint, "GET", ByteArray(0), hostHeader)
        } catch (_: Exception) {
          throw IllegalStateException("HTTP source IP probe failed.")
        }
    if (response.status != 200) {
      throw IllegalStateException("HTTP source IP probe did not return status 200.")
    }
    val observedIp =
        extractObservedIp(response.body)
            ?: throw IllegalStateException("HTTP response did not contain a numeric source IP.")
    instrumentation.sendStatus(
        0,
        Bundle().apply { putString("observedSourceIp", observedIp) },
    )
  }

  @Test
  fun selfSocketOwnerProbe() {
    ensureAuthorizedVpn()
    requireExpectedRoutingMode()
    val endpoint = sourceIpUrl()
    optionalSourceIpHost() // Validate the optional Host argument with the same strict rules.

    val numericTarget =
        normalizeNumericIp(endpoint.host)
            ?: throw IllegalStateException("sourceIpUrl must use a numeric IP address.")
    val targetAddress = InetAddress.getByName(numericTarget)
    val targetPort = endpoint.port.takeIf { it > 0 } ?: 80
    val socket = Socket()
    var socketConnected = false
    var ownSourceIp = ""
    var ownSourcePort = -1
    var ownerUid = -1
    var ownerApiSucceeded = false
    var ownerErrorClass = ""
    var socketErrorClass = ""
    try {
      socket.connect(InetSocketAddress(targetAddress, targetPort), PROBE_TIMEOUT_MS)
      socketConnected = true
      val local = socket.localSocketAddress as? InetSocketAddress
      val remote = socket.remoteSocketAddress as? InetSocketAddress
      ownSourceIp = local?.address?.hostAddress?.let(::normalizeNumericIp).orEmpty()
      ownSourcePort = local?.port ?: -1
      if (local != null && remote != null) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
          try {
            val connectivity =
                context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            ownerUid = connectivity.getConnectionOwnerUid(OsConstants.IPPROTO_TCP, local, remote)
            ownerApiSucceeded = true
          } catch (error: Exception) {
            ownerErrorClass = error.javaClass.simpleName
          }
        } else {
          ownerErrorClass = "ApiUnavailable"
        }
      } else {
        ownerErrorClass = "SocketAddressUnavailable"
      }
    } catch (error: Exception) {
      socketErrorClass = error.javaClass.simpleName
    } finally {
      try {
        socket.close()
      } catch (_: Exception) {
        // The diagnostic result is collected after the owner lookup.
      }
    }

    val expectedUid = Process.myUid()
    val expectedPackage = context.packageName
    var returnedPackages = emptyList<String>()
    var ownerPackageMatch = false
    var ownerPackageCount = -1
    if (ownerApiSucceeded && ownerUid == expectedUid) {
      try {
        returnedPackages = context.packageManager.getPackagesForUid(ownerUid)?.toList().orEmpty()
        ownerPackageCount = returnedPackages.size
        ownerPackageMatch = expectedPackage in returnedPackages
      } catch (_: Exception) {
        ownerPackageCount = -1
      }
    }
    val interfaceAddresses = tailscaleInterfaceAddresses()
    val result =
        Bundle().apply {
          putBoolean("socketConnected", socketConnected)
          putString("ownSourceIp", ownSourceIp)
          putInt("ownSourcePort", ownSourcePort)
          putInt("ownerUid", ownerUid)
          putInt("expectedUid", expectedUid)
          putString("expectedPackage", expectedPackage)
          putBoolean("ownerApiSucceeded", ownerApiSucceeded)
          putString("ownerErrorClass", ownerErrorClass)
          putString("socketErrorClass", socketErrorClass)
          putBoolean("ownerPackageMatch", ownerPackageMatch)
          putInt("ownerPackageCount", ownerPackageCount)
          putBoolean("sourceListedInInterfaces", ownSourceIp in interfaceAddresses)
          putStringArrayList(
              "tailscaleInterfaceAddresses",
              interfaceAddresses.toCollection(ArrayList()),
          )
          if (ownerApiSucceeded && ownerUid == expectedUid && ownerPackageCount >= 0) {
            putStringArrayList("returnedPackages", returnedPackages.toCollection(ArrayList()))
          }
        }
    instrumentation.sendStatus(0, result)
    assertTrue("TCP socket to the source IP endpoint did not connect.", socketConnected)
    assertTrue("Connection owner lookup did not succeed.", ownerApiSucceeded)
    assertEquals("Connection owner UID did not match this process.", expectedUid, ownerUid)
    assertTrue("Connection owner UID did not include the target package.", ownerPackageMatch)
  }

  @Test
  fun dnsResolutionProbe() {
    ensureAuthorizedVpn()
    requireExpectedRoutingMode()
    val dnsName =
        validatedDnsName(
            InstrumentationRegistry.getArguments().getString("dnsName") ?: DEFAULT_DNS_NAME
        )
    val addresses = resolveDnsBounded(dnsName)
    assertTrue("DNS resolution returned no numeric IP addresses.", addresses.isNotEmpty())
    instrumentation.sendStatus(
        0,
        Bundle().apply {
          putStringArrayList("resolvedNumericIPs", addresses.toCollection(ArrayList()))
        },
    )
  }

  @Test
  fun udpDnsProbe() {
    ensureAuthorizedVpn()
    requireExpectedRoutingMode()
    val arguments = InstrumentationRegistry.getArguments()
    val dnsServer =
        normalizeNumericIp(arguments.getString("dnsServer") ?: DEFAULT_DNS_SERVER)
            ?: throw IllegalStateException("Supply a numeric DNS server address.")
    val dnsName = validatedDnsName(arguments.getString("dnsName") ?: DEFAULT_DNS_NAME)
    val (answerCount, rcode) = queryDnsOverUdp(dnsServer, dnsName)
    assertTrue("UDP DNS probe did not return a successful answer.", rcode == 0 && answerCount > 0)
    instrumentation.sendStatus(
        0,
        Bundle().apply {
          putInt("dnsAnswerCount", answerCount)
          putInt("dnsRcode", rcode)
          putString("dnsServer", dnsServer)
        },
    )
  }

  @Test
  fun tailnetTcpProbe() {
    ensureAuthorizedVpn()
    requireExpectedRoutingMode()
    val arguments = InstrumentationRegistry.getArguments()
    val rawAddress = arguments.getString("tailnetIp")?.trim().orEmpty()
    val address =
        normalizeNumericIp(rawAddress)
            ?: throw IllegalStateException("Supply a numeric Tailscale IP address.")
    val port = arguments.getString("tailnetPort")?.toIntOrNull()
    if (port == null || port !in 1..65_535) {
      throw IllegalStateException("Supply a Tailscale TCP port from 1 to 65535.")
    }
    val inetAddress = InetAddress.getByName(address)
    if (!isTailscaleAddress(inetAddress)) {
      throw IllegalStateException("The requested address is outside the Tailscale IP ranges.")
    }
    val connected =
        try {
          Socket().use { socket ->
            socket.connect(InetSocketAddress(inetAddress, port), PROBE_TIMEOUT_MS)
            true
          }
        } catch (_: Exception) {
          false
        }
    instrumentation.sendStatus(0, Bundle().apply { putBoolean("connected", connected) })
    assertTrue("TCP connection to the requested Tailscale service failed.", connected)
  }

  @Test
  fun failedHttpEchoRouteDoesNotFallBackToDirect() {
    requireProbePrerequisites()
    val arguments = InstrumentationRegistry.getArguments()
    assertTrue(
        "Run directHttpBaselineRespondsWhileRoutingIsDisabled before testing failure",
        arguments.getString("directBaselineConfirmed") == "true",
    )
    val endpoint = probeUrl()

    try {
      val response = request(endpoint, "GET", ByteArray(0))
      assertTrue(
          "The public endpoint returned HTTP ${response.status}; routing may have fallen back",
          false,
      )
    } catch (_: IOException) {
      // A stopped/unreachable route should fail the app's HTTP connection.
    }
  }

  private fun requireActiveVpn() {
    ensureAuthorizedVpn()
  }

  private fun requireProbePrerequisites() {
    ensureAuthorizedVpn()
    var latestVpnActive = false
    var latestBackendRunning = false
    var latestRoutingStatus = "Unavailable"
    val ready = awaitPrerequisite {
      latestVpnActive = isVpnActive()
      latestBackendRunning = backendIsRunning()
      latestRoutingStatus = safeRoutingStatus()
      latestVpnActive && latestBackendRunning && latestRoutingStatus.startsWith("Rules active")
    }
    assertTrue(
        "VPN and routing prerequisites were not ready within 20 seconds " +
            "(VPN active: $latestVpnActive, backend Running: $latestBackendRunning, " +
            "routing status: $latestRoutingStatus).",
        ready,
    )
  }

  private fun ensureAuthorizedVpn() {
    val alreadyAuthorized =
        try {
          VpnService.prepare(context) == null
        } catch (_: Exception) {
          false
        }
    assertTrue("VPN permission is not already authorized.", alreadyAuthorized)
    try {
      instrumentation.runOnMainSync { UninitializedApp.get().startVPN() }
    } catch (_: Exception) {
      throw IllegalStateException("Authorized VPN start request failed.")
    }
    val ready = awaitPrerequisite(VPN_START_TIMEOUT_MS) { isVpnActive() && backendIsRunning() }
    assertTrue(
        "Authorized Tailscale VPN did not become active and Running within 30 seconds.",
        ready,
    )
  }

  private fun awaitPrerequisite(
      timeoutMs: Long = PREREQUISITE_TIMEOUT_MS,
      isReady: () -> Boolean,
  ): Boolean {
    val deadline = SystemClock.elapsedRealtime() + timeoutMs
    while (true) {
      if (isReady()) return true
      val remaining = deadline - SystemClock.elapsedRealtime()
      if (remaining <= 0) return false
      SystemClock.sleep(minOf(PREREQUISITE_POLL_INTERVAL_MS, remaining))
    }
  }

  private fun isVpnActive(): Boolean {
    return try {
      val connectivity =
          context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
      val active = connectivity.activeNetwork
      val capabilities = active?.let(connectivity::getNetworkCapabilities)
      capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    } catch (_: Exception) {
      false
    }
  }

  private fun backendIsRunning(): Boolean {
    return try {
      val response = app.callLocalAPI(LOCAL_API_TIMEOUT_MS, "GET", "/localapi/v0/status", null)
      if (response.statusCode() !in 200..299) return false
      val bytes = response.bodyBytes() ?: return false
      Json.parseToJsonElement(String(bytes, StandardCharsets.UTF_8))
          .jsonObject["BackendState"]
          ?.jsonPrimitive
          ?.contentOrNull == BACKEND_RUNNING
    } catch (_: Exception) {
      false
    }
  }

  private fun safeRoutingStatus(): String {
    return try {
      app.routingStatus()
    } catch (_: Exception) {
      "Unavailable"
    }
  }

  private fun sourceIpUrl(): URI {
    val raw = InstrumentationRegistry.getArguments().getString("sourceIpUrl")?.trim()
    if (raw.isNullOrEmpty()) {
      throw IllegalStateException("Supply -e sourceIpUrl http://<numeric-ip>/path.")
    }
    val endpoint =
        try {
          URI(raw)
        } catch (_: Exception) {
          throw IllegalStateException("sourceIpUrl must be a valid numeric HTTP URL.")
        }
    if (
        endpoint.scheme != "http" ||
            endpoint.userInfo != null ||
            endpoint.host.isNullOrEmpty() ||
            normalizeNumericIp(endpoint.host) == null ||
            (endpoint.port != -1 && endpoint.port !in 1..65_535)
    ) {
      throw IllegalStateException("sourceIpUrl must be a numeric HTTP URL without credentials.")
    }
    return endpoint
  }

  private fun optionalSourceIpHost(): String? {
    val host = InstrumentationRegistry.getArguments().getString("sourceIpHost") ?: return null
    if (
        host.isEmpty() ||
            host.length > 253 ||
            host.any { it == '\r' || it == '\n' || it.code < 0x20 || it.code == 0x7f }
    ) {
      throw IllegalStateException("sourceIpHost is not a valid Host header value.")
    }
    val normalized = host.removeSuffix(".")
    val labels = normalized.split('.')
    val labelPattern = Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    if (normalized.isEmpty() || labels.any { !labelPattern.matches(it) }) {
      throw IllegalStateException("sourceIpHost is not a valid Host header value.")
    }
    return host
  }

  private fun validatedDnsName(raw: String): String {
    val name = raw.trim().removeSuffix(".")
    val labelPattern = Regex("[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
    if (name.isEmpty() || name.length > 253 || name.split('.').any { !labelPattern.matches(it) }) {
      throw IllegalStateException("dnsName must be a valid DNS name.")
    }
    return name
  }

  private fun resolveDnsBounded(name: String): List<String> {
    val executor = Executors.newSingleThreadExecutor { runnable ->
      Thread(runnable, "dns-resolution-probe").apply { isDaemon = true }
    }
    try {
      val future = executor.submit(Callable { InetAddress.getAllByName(name) })
      return future
          .get(DNS_PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
          .mapNotNull { normalizeNumericIp(it.hostAddress) }
          .distinct()
    } catch (_: TimeoutException) {
      return emptyList()
    } catch (_: Exception) {
      return emptyList()
    } finally {
      executor.shutdownNow()
    }
  }

  private fun queryDnsOverUdp(server: String, name: String): Pair<Int, Int> {
    val serverAddress =
        try {
          InetAddress.getByName(server)
        } catch (_: Exception) {
          throw IllegalStateException("UDP DNS server address is invalid.")
        }
    val transactionId = SecureRandom().nextInt(1 shl 16)
    val query = buildDnsQuery(name, transactionId)
    try {
      DatagramSocket().use { socket ->
        socket.soTimeout = DNS_PROBE_TIMEOUT_MS.toInt()
        socket.connect(serverAddress, DNS_PORT)
        socket.send(DatagramPacket(query, query.size, serverAddress, DNS_PORT))
        val packetBuffer = ByteArray(MAX_DNS_PACKET_BYTES)
        val responsePacket = DatagramPacket(packetBuffer, packetBuffer.size)
        socket.receive(responsePacket)
        if (responsePacket.length < DNS_HEADER_BYTES) {
          throw IllegalStateException("UDP DNS response was incomplete.")
        }
        val response = responsePacket.data.copyOf(responsePacket.length)
        val responseId = readUnsignedShort(response, 0)
        val flags = readUnsignedShort(response, 2)
        if (responseId != transactionId || flags and DNS_QR_MASK == 0) {
          throw IllegalStateException("UDP DNS response did not match the query.")
        }
        if (readUnsignedShort(response, 4) != 1) {
          throw IllegalStateException("UDP DNS response had an unexpected question count.")
        }
        return readUnsignedShort(response, 6) to (flags and DNS_RCODE_MASK)
      }
    } catch (_: Exception) {
      throw IllegalStateException("UDP DNS probe failed.")
    }
  }

  private fun buildDnsQuery(name: String, transactionId: Int): ByteArray {
    val output = ByteArrayOutputStream()
    output.write((transactionId ushr 8) and 0xff)
    output.write(transactionId and 0xff)
    output.write(0x01) // Recursion desired.
    output.write(0x00)
    output.write(0x00)
    output.write(0x01) // One question.
    output.write(ByteArray(6)) // ANCOUNT, NSCOUNT, and ARCOUNT.
    name.split('.').forEach { label ->
      val bytes = label.toByteArray(StandardCharsets.US_ASCII)
      output.write(bytes.size)
      output.write(bytes)
    }
    output.write(0)
    output.write(0)
    output.write(1) // A record.
    output.write(0)
    output.write(1) // IN class.
    return output.toByteArray()
  }

  private fun readUnsignedShort(bytes: ByteArray, offset: Int): Int {
    return ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
  }

  private fun isTailscaleAddress(address: InetAddress): Boolean {
    val bytes = address.address.map { it.toInt() and 0xff }
    if (bytes.size == 4) return bytes[0] == 100 && bytes[1] in 64..127
    val prefix = listOf(0xfd, 0x7a, 0x11, 0x5c, 0xa1, 0xe0)
    return address is Inet6Address && bytes.take(prefix.size) == prefix
  }

  private fun tailscaleInterfaceAddresses(): List<String> {
    return try {
      val interfaces =
          Json.parseToJsonElement(App.get().getInterfacesAsJson()) as? JsonArray
              ?: return emptyList()
      val addresses = ArrayList<String>()
      for (interfaceElement in interfaces) {
        val interfaceObject = interfaceElement as? JsonObject ?: continue
        val interfaceAddresses = interfaceObject["addrs"] as? JsonArray ?: continue
        for (addressElement in interfaceAddresses) {
          val addressObject = addressElement as? JsonObject ?: continue
          val rawAddress = (addressObject["ip"] as? JsonPrimitive)?.contentOrNull ?: continue
          val numericAddress = normalizeNumericIp(rawAddress) ?: continue
          val parsedAddress = InetAddress.getByName(numericAddress)
          if (isTailscaleAddress(parsedAddress)) addresses.add(numericAddress)
        }
      }
      addresses.distinct()
    } catch (_: Exception) {
      emptyList()
    }
  }

  private fun normalizeNumericIp(raw: String): String? {
    val candidate = raw.removePrefix("[").removeSuffix("]")
    if (isNumericIpv4(candidate)) return candidate
    if (':' !in candidate || candidate.any { it !in "0123456789abcdefABCDEF:." }) return null
    return try {
      val address = InetAddress.getByName(candidate)
      if (address is Inet6Address) address.hostAddress.substringBefore('%') else null
    } catch (_: Exception) {
      null
    }
  }

  private fun requireExpectedRoutingMode() {
    val expected = InstrumentationRegistry.getArguments().getString("expectedRouting") ?: return
    val status = safeRoutingStatus()
    val matches =
        when (expected) {
          EXPECT_ROUTING_DISABLED -> status == "Disabled"
          EXPECT_ROUTING_RULES -> status.startsWith("Rules active")
          else -> throw IllegalStateException("expectedRouting must be Disabled or Rules.")
        }
    if (!matches) throw IllegalStateException("Requested routing mode is not active.")
  }

  private fun probeUrl(): URI {
    val raw = InstrumentationRegistry.getArguments().getString("probeUrl")
    assertTrue("Supply -e probeUrl http://example.com/", !raw.isNullOrBlank())
    val endpoint = URI(raw)
    assertEquals("The public probe uses HTTP", "http", endpoint.scheme)
    assertTrue("Credentials are not allowed in the probe URL", endpoint.userInfo == null)
    assertTrue("The probe URL must include a host", !endpoint.host.isNullOrBlank())
    return endpoint
  }

  private fun numericProbeUrl(): URI {
    val endpoint = probeUrl()
    assertTrue(
        "Supply -e probeUrl http://<numeric-public-ip>/path for this routing GET probe",
        isNumericIpv4(endpoint.host),
    )
    return endpoint
  }

  private fun extractObservedIp(body: ByteArray): String? {
    val text = String(body, StandardCharsets.UTF_8).trim()
    normalizeNumericIp(text)?.let {
      return it
    }
    text.lineSequence().forEach { line ->
      if (line.startsWith("ip=", ignoreCase = true)) {
        normalizeNumericIp(line.substringAfter('=').trim())?.let {
          return it
        }
      }
    }
    val json =
        try {
          Json.parseToJsonElement(text) as? JsonObject
        } catch (_: Exception) {
          null
        } ?: return null
    val ipValue = (json["ip"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull
    normalizeNumericIp(ipValue.orEmpty())?.let {
      return it
    }
    val origin = (json["origin"] as? kotlinx.serialization.json.JsonPrimitive)?.contentOrNull
    origin?.split(',')?.forEach { candidate ->
      normalizeNumericIp(candidate.trim())?.let {
        return it
      }
    }
    return null
  }

  private fun isNumericIpv4(host: String): Boolean {
    val octets = host.split('.')
    return octets.size == 4 &&
        octets.all { octet ->
          octet.isNotEmpty() &&
              (octet == "0" || !octet.startsWith('0')) &&
              octet.all(Char::isDigit) &&
              octet.toIntOrNull()?.let { it in 0..255 } == true
        }
  }

  private fun echoUrl(): URI {
    val raw = InstrumentationRegistry.getArguments().getString("echoUrl")
    assertTrue(
        "Supply -e echoUrl http://<reachable-fixture-address>:<port>/echo",
        !raw.isNullOrBlank(),
    )
    val endpoint = URI(raw)
    assertEquals("The echo fixture uses HTTP", "http", endpoint.scheme)
    assertTrue("Credentials are not allowed in the echo URL", endpoint.userInfo == null)
    assertTrue(
        "The echo URL must include a host and port",
        !endpoint.host.isNullOrBlank() && endpoint.port > 0,
    )
    return endpoint
  }

  private fun request(
      endpoint: URI,
      method: String,
      payload: ByteArray,
      hostOverride: String? = null,
  ): ProbeResponse {
    require(method == "GET" || method == "POST")
    val socket = Socket()
    socket.soTimeout = PROBE_TIMEOUT_MS
    val port = endpoint.port.takeIf { it > 0 } ?: 80
    val connectHost = normalizeNumericIp(endpoint.host) ?: endpoint.host
    val connectAddress = InetAddress.getByName(connectHost)
    socket.connect(InetSocketAddress(connectAddress, port), PROBE_TIMEOUT_MS)
    socket.use { connection ->
      val path = endpoint.rawPath.ifEmpty { "/" } + (endpoint.rawQuery?.let { "?$it" } ?: "")
      val urlHost = connectHost.let { if (':' in it && !it.startsWith("[")) "[$it]" else it }
      val hostValue = hostOverride ?: "$urlHost:$port"
      if (hostValue.any { it == '\r' || it == '\n' || it.code < 0x20 || it.code == 0x7f }) {
        throw IOException("Invalid HTTP Host header")
      }
      val request = buildString {
        append("$method $path HTTP/1.1\r\n")
        append("Host: $hostValue\r\n")
        append("Connection: close\r\n")
        append("Accept-Encoding: identity\r\n")
        if (method == "POST") {
          append("Content-Type: application/octet-stream\r\n")
          append("Content-Length: ${payload.size}\r\n")
        }
        append("\r\n")
      }
      connection.getOutputStream().apply {
        write(request.toByteArray(StandardCharsets.US_ASCII))
        if (method == "POST") write(payload)
        flush()
      }

      val input = connection.getInputStream()
      val statusLine = input.readHttpLine(MAX_HTTP_HEADER_BYTES)
      val status =
          Regex("HTTP/1\\.[01] ([0-9]{3})(?: |$)").find(statusLine)?.groupValues?.get(1)?.toInt()
              ?: throw IOException("Invalid HTTP status line")
      var contentLength: Int? = null
      var transferEncoding = ""
      var headerBytes = statusLine.length + 2
      while (true) {
        val line = input.readHttpLine(MAX_HTTP_HEADER_BYTES - headerBytes)
        headerBytes += line.length + 2
        if (headerBytes > MAX_HTTP_HEADER_BYTES) throw IOException("HTTP headers exceed test limit")
        if (line.isEmpty()) break
        val name = line.substringBefore(':').trim()
        val value = line.substringAfter(':', "").trim()
        if (name.equals("Content-Length", ignoreCase = true)) {
          val parsed = value.toIntOrNull() ?: throw IOException("Invalid HTTP content length")
          if (parsed < 0 || (contentLength != null && contentLength != parsed)) {
            throw IOException("Invalid HTTP content length")
          }
          contentLength = parsed
        } else if (name.equals("Transfer-Encoding", ignoreCase = true)) {
          transferEncoding = value
        }
      }
      val body = readResponseBody(input, contentLength, transferEncoding)
      return ProbeResponse(status, body)
    }
  }

  private fun readResponseBody(
      input: java.io.InputStream,
      contentLength: Int?,
      transferEncoding: String,
  ): ByteArray {
    if (transferEncoding.split(',').any { it.trim().equals("chunked", ignoreCase = true) }) {
      return input.readChunkedBody()
    }
    if (contentLength != null) {
      if (contentLength !in 0..MAX_HTTP_BODY_BYTES) {
        throw IOException("HTTP response body exceeds test limit")
      }
      return input.readExactly(contentLength)
    }
    return input.readBodyUntilEof()
  }

  private fun java.io.InputStream.readChunkedBody(): ByteArray {
    val output = ByteArrayOutputStream()
    var trailerBytes = 0
    while (true) {
      val chunkLine = readHttpLine(MAX_HTTP_HEADER_BYTES)
      val chunkSize = chunkLine.substringBefore(';').trim().toLongOrNull(16)
      if (
          chunkSize == null ||
              chunkSize < 0 ||
              chunkSize > (MAX_HTTP_BODY_BYTES - output.size()).toLong()
      ) {
        throw IOException("Invalid or oversized HTTP chunk")
      }
      if (chunkSize == 0L) {
        while (true) {
          val trailer = readHttpLine(MAX_HTTP_HEADER_BYTES - trailerBytes)
          trailerBytes += trailer.length + 2
          if (trailerBytes > MAX_HTTP_HEADER_BYTES)
              throw IOException("HTTP trailers exceed test limit")
          if (trailer.isEmpty()) return output.toByteArray()
        }
      }
      output.write(readExactly(chunkSize.toInt()))
      if (read() != '\r'.code || read() != '\n'.code) {
        throw IOException("Invalid HTTP chunk terminator")
      }
    }
  }

  private fun java.io.InputStream.readBodyUntilEof(): ByteArray {
    val output = ByteArrayOutputStream()
    val buffer = ByteArray(4096)
    while (true) {
      val allowed = MAX_HTTP_BODY_BYTES - output.size() + 1
      val count = read(buffer, 0, minOf(buffer.size, allowed))
      if (count < 0) return output.toByteArray()
      if (output.size() + count > MAX_HTTP_BODY_BYTES) {
        throw IOException("HTTP response body exceeds test limit")
      }
      if (count > 0) output.write(buffer, 0, count)
    }
  }

  private data class ProbeResponse(val status: Int, val body: ByteArray)

  private fun java.io.InputStream.readHttpLine(maxBytes: Int): String {
    if (maxBytes <= 0) throw IOException("HTTP headers exceed test limit")
    val bytes = ByteArrayOutputStream()
    while (bytes.size() <= maxBytes) {
      val next = read()
      if (next < 0) throw IOException("Unexpected end of HTTP response")
      if (next == '\n'.code) {
        val line = bytes.toByteArray()
        val size = if (line.lastOrNull() == '\r'.code.toByte()) line.size - 1 else line.size
        return String(line, 0, size, StandardCharsets.ISO_8859_1)
      }
      bytes.write(next)
    }
    throw IOException("HTTP header line exceeds test limit")
  }

  private fun java.io.InputStream.readExactly(length: Int): ByteArray {
    val output = ByteArray(length)
    var offset = 0
    while (offset < length) {
      val read = read(output, offset, length - offset)
      if (read < 0) throw IOException("Unexpected end of HTTP response body")
      offset += read
    }
    return output
  }

  private object ApplicationSample {
    // Keep this minimal: validation starts the engine but does not start traffic or mutate profile.
    val configuration =
        """{"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}"""
  }

  private companion object {
    const val PREREQUISITE_TIMEOUT_MS = 20_000L
    const val VPN_START_TIMEOUT_MS = 30_000L
    const val PREREQUISITE_POLL_INTERVAL_MS = 500L
    const val LOCAL_API_TIMEOUT_MS = 2_000L
    const val BACKEND_RUNNING = "Running"
    const val PROBE_TIMEOUT_MS = 5_000
    const val DNS_PROBE_TIMEOUT_MS = 5_000L
    const val DNS_PORT = 53
    const val DNS_HEADER_BYTES = 12
    const val DNS_QR_MASK = 0x8000
    const val DNS_RCODE_MASK = 0x000f
    const val MAX_DNS_PACKET_BYTES = 4096
    const val MAX_HTTP_HEADER_BYTES = 16 * 1024
    const val MAX_HTTP_BODY_BYTES = 64 * 1024
    const val MAX_ECHO_BYTES = 64 * 1024
    const val DEFAULT_DNS_NAME = "example.com"
    const val DEFAULT_DNS_SERVER = "1.1.1.1"
    const val EXPECT_ROUTING_DISABLED = "Disabled"
    const val EXPECT_ROUTING_RULES = "Rules"
  }
}
