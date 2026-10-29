// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Bundle
import android.os.SystemClock
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.tailscale.ipn.ui.util.InputStreamAdapter
import java.io.File
import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import java.nio.charset.StandardCharsets
import java.security.cert.CertificateException
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import libtailscale.Application
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Explicitly gated device controls for the regression client and routing profile. */
@RunWith(AndroidJUnit4::class)
class RegressionControlTest {
  private val instrumentation = InstrumentationRegistry.getInstrumentation()
  private val context: Context
    get() = instrumentation.targetContext

  private lateinit var app: App
  private lateinit var libtailscaleApp: Application

  @Before
  fun openMainApp() {
    context.startActivity(
        Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
    )
    instrumentation.waitForIdleSync()
    app = App.get()
    libtailscaleApp = app.getLibtailscaleApp()
  }

  @Test
  fun registerRegressionClient() {
    if (!isOperation(OP_REGISTER)) return

    try {
      val initialStatus = localApiJson("GET", "status").jsonObject
      val initialState = initialStatus.stringValue("BackendState")
      val self = initialStatus.objectValue("Self")
      val selfId = self?.stringValue("ID").orEmpty()
      if (selfId.isNotEmpty() && initialState != STATE_NEEDS_LOGIN) {
        if (self?.stringValue("HostName") != REGRESSION_HOSTNAME) {
          patchAndVerifyHostname(includeLoginPrefs = false)
        }
        emitRegressionStatus()
        return
      }

      // Set and verify the registration hostname before /start can create a new node.
      val rawPrefs = patchAndVerifyHostname(includeLoginPrefs = true).toMutableMap()
      emitRegistrationStage(STAGE_PREFS_VERIFIED)
      rawPrefs["WantRunning"] = JsonPrimitive(true)
      val authKey = readAndDeleteAuthKey()
      runOnMain { app.startForegroundForLogin() }
      val startBody = buildJsonObject {
        put("UpdatePrefs", JsonObject(rawPrefs))
        put("AuthKey", authKey)
      }
      localApiJson("POST", "start", startBody)
      emitRegistrationStage(STAGE_START_ACCEPTED)
      localApiJson("POST", "login-interactive")
      emitRegistrationStage(STAGE_LOGIN_REQUESTED)

      runOnMain { UninitializedApp.get().startVPN() }
      emitRegistrationStage(STAGE_VPN_REQUESTED)
      waitForRunning()
      emitRegressionStatus()
    } finally {
      File(context.cacheDir, AUTH_KEY_FILENAME).delete()
    }
  }

  @Test
  fun reportRegressionStatus() {
    if (!isOperation(OP_STATUS)) return
    emitRegressionStatus()
  }

  @Test
  fun probeRegressionControlPlane() {
    if (!isOperation(OP_CONTROL_PROBE)) return

    var connection: HttpsURLConnection? = null
    val result = Bundle()
    try {
      connection = URL(CONTROL_PLANE_KEY_URL).openConnection() as HttpsURLConnection
      connection.connectTimeout = CONTROL_PROBE_TIMEOUT_MS
      connection.readTimeout = CONTROL_PROBE_TIMEOUT_MS
      connection.requestMethod = "GET"
      result.putInt("controlProbeHttpStatus", connection.responseCode)
    } catch (error: Exception) {
      result.putString("controlProbeCategory", controlProbeExceptionCategory(error))
      result.putString("controlProbeExceptionClass", error.javaClass.simpleName)
    } finally {
      connection?.disconnect()
    }
    instrumentation.sendStatus(0, result)
  }

  @Test
  fun applyRegressionProfile() {
    if (!isOperation(OP_APPLY)) return

    ensureAuthorizedVpn()
    val profile = readAndDeleteFile("regression-profile.json", "Regression profile is unavailable.")
    try {
      libtailscaleApp.validateRoutingConfig(profile)
      libtailscaleApp.applyRoutingConfig(profile)
    } catch (_: Exception) {
      throw IllegalStateException("Regression profile operation failed.")
    }
  }

  @Test
  fun disableRegressionRouting() {
    if (!isOperation(OP_DISABLE)) return

    ensureAuthorizedVpn()
    try {
      libtailscaleApp.disableRouting()
    } catch (_: Exception) {
      throw IllegalStateException("Regression routing disable failed.")
    }
  }

  @Test
  fun selectRegressionExitNode() {
    if (!isOperation(OP_SELECT_EXIT)) return

    ensureAuthorizedVpn()
    val requestedId =
        InstrumentationRegistry.getArguments().getString(ARG_EXIT_NODE_ID)?.trim()?.takeIf {
          it.isNotEmpty()
        } ?: throw IllegalStateException("Supply the requested regression exit node ID.")
    val peers = localApiJson("GET", "status").jsonObject.objectValue("Peer")?.values.orEmpty()
    val selectedPeer =
        peers.firstOrNull { peerElement ->
          val peer = peerElement.jsonObject
          peer.stringValue("ID") == requestedId &&
              peer.booleanValue("ExitNodeOption") &&
              peer.booleanValue("Online")
        }
            ?: throw IllegalStateException(
                "Requested regression exit node is not eligible and online."
            )
    val peer = selectedPeer.jsonObject
    if (peer.stringValue("HostName").isEmpty()) {
      throw IllegalStateException("Requested regression exit node has no hostname.")
    }
    val updatedPrefs =
        localApiJson(
                "PATCH",
                "prefs",
                buildJsonObject {
                  put("ExitNodeIDSet", true)
                  put("ExitNodeID", requestedId)
                },
            )
            .jsonObject
    if (updatedPrefs.stringValue("ExitNodeID") != requestedId) {
      throw IllegalStateException("Regression exit node selection could not be verified.")
    }
    emitRegressionStatus()
  }

  @Test
  fun clearRegressionExitNode() {
    if (!isOperation(OP_CLEAR_EXIT)) return

    ensureAuthorizedVpn()
    val updatedPrefs =
        localApiJson(
                "PATCH",
                "prefs",
                buildJsonObject {
                  put("ExitNodeIDSet", true)
                  put("ExitNodeID", "")
                },
            )
            .jsonObject
    if (updatedPrefs.stringValue("ExitNodeID").isNotEmpty()) {
      throw IllegalStateException("Regression exit node clearing could not be verified.")
    }
    emitRegressionStatus()
  }

  private fun emitRegressionStatus() {
    val status = localApiJson("GET", "status").jsonObject
    val prefs = localApiJson("GET", "prefs").jsonObject
    val self = status.objectValue("Self")
    val configNodeId = prefs.objectValue("Config")?.stringValue("NodeID").orEmpty()
    val persistNodeId = configNodeId.ifEmpty { prefs.stringValue("NodeID") }
    val peers = status.objectValue("Peer")?.values.orEmpty()
    val eligibleExitNodes = peers.mapNotNull { peerElement ->
      val peer = peerElement.jsonObject
      if (!peer.booleanValue("ExitNodeOption")) return@mapNotNull null
      val id = peer.stringValue("ID")
      val hostname = peer.stringValue("HostName")
      if (id.isEmpty() || hostname.isEmpty()) return@mapNotNull null
      Triple(id, hostname, peer.booleanValue("Online"))
    }
    val result =
        Bundle().apply {
          putString("hostname", self?.stringValue("HostName").orEmpty())
          putString("backendState", status.stringValue("BackendState"))
          putString("routingStatus", safeRoutingStatus())
          putBoolean("vpnActive", isVpnActive())
          putString("prefsHostname", prefs.stringValue("Hostname"))
          putBoolean("prefsWantRunning", prefs.booleanValue("WantRunning"))
          putBoolean("prefsLoggedOut", prefs.booleanValue("LoggedOut"))
          putBoolean("authUrlPresent", status.stringValue("AuthURL").isNotEmpty())
          putBoolean("persistNodeIdPresent", persistNodeId.isNotEmpty())
          putStringArrayList("healthCategories", healthCategories(status).toCollection(ArrayList()))
          putStringArrayList(
              "selfTailscaleIPs",
              status.arrayValue("TailscaleIPs").stringValues().toCollection(ArrayList()),
          )
          putStringArrayList(
              "eligibleExitIDs",
              eligibleExitNodes.map { it.first }.toCollection(ArrayList()),
          )
          putStringArrayList(
              "eligibleExitHostnames",
              eligibleExitNodes.map { it.second }.toCollection(ArrayList()),
          )
          putStringArrayList(
              "eligibleExitOnline",
              eligibleExitNodes.map { it.third.toString() }.toCollection(ArrayList()),
          )
          putStringArrayList(
              "onlineEligibleExitIDs",
              eligibleExitNodes.filter { it.third }.map { it.first }.toCollection(ArrayList()),
          )
          putString("selectedexit", prefs.stringValue("ExitNodeID"))
        }
    instrumentation.sendStatus(0, result)
  }

  private fun safeRoutingStatus(): String {
    return try {
      libtailscaleApp.routingStatus()
    } catch (_: Exception) {
      "Unavailable"
    }
  }

  private fun isVpnActive(): Boolean {
    return try {
      val connectivity =
          context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
      val activeNetwork = connectivity.activeNetwork ?: return false
      connectivity
          .getNetworkCapabilities(activeNetwork)
          ?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
    } catch (_: Exception) {
      false
    }
  }

  private fun healthCategories(status: JsonObject): List<String> {
    return status
        .arrayValue("Health")
        .mapNotNull { element ->
          val message = (element as? JsonPrimitive)?.contentOrNull?.lowercase()
          if (message == null) return@mapNotNull null
          when {
            isAuthKeyIssue(message, "used", "consumed", "already used") -> HEALTH_AUTH_KEY_USED
            isAuthKeyIssue(message, "expired", "expiry") -> HEALTH_AUTH_KEY_EXPIRED
            isAuthKeyIssue(message, "invalid", "malformed", "not valid") -> HEALTH_AUTH_KEY_INVALID
            "dns" in message -> HEALTH_DNS
            "tls" in message || "certificate" in message || "handshake" in message -> HEALTH_TLS
            "timeout" in message || "timed out" in message || "deadline" in message ->
                HEALTH_TIMEOUT
            "control" in message -> HEALTH_CONTROL
            "auth" in message || "login" in message || "machine key" in message -> HEALTH_AUTH
            "network" in message || "connection" in message || "relay" in message -> HEALTH_NETWORK
            else -> HEALTH_OTHER
          }
        }
        .distinct()
  }

  private fun isAuthKeyIssue(message: String, vararg terms: String): Boolean {
    val mentionsAuthKey = "authkey" in message || ("auth" in message && "key" in message)
    return mentionsAuthKey && terms.any { it in message }
  }

  private fun emitRegistrationStage(stage: String) {
    instrumentation.sendStatus(0, Bundle().apply { putString("registrationStage", stage) })
  }

  private fun controlProbeExceptionCategory(error: Exception): String {
    return when (error) {
      is UnknownHostException -> CONTROL_ERROR_DNS
      is SocketTimeoutException -> CONTROL_ERROR_TIMEOUT
      is SSLException,
      is CertificateException -> CONTROL_ERROR_TLS
      is ConnectException -> CONTROL_ERROR_CONNECT
      else -> CONTROL_ERROR_OTHER
    }
  }

  private fun waitForRunning() {
    val deadline = SystemClock.elapsedRealtime() + REGISTRATION_TIMEOUT_MS
    while (SystemClock.elapsedRealtime() < deadline) {
      val state = localApiJson("GET", "status").jsonObject.stringValue("BackendState")
      if (state == STATE_RUNNING) return
      SystemClock.sleep(STATUS_POLL_INTERVAL_MS)
    }
    try {
      emitRegressionStatus()
    } catch (_: Exception) {
      // Keep timeout failures generic even when final status collection is unavailable.
    }
    throw IllegalStateException("Regression client did not reach Running before timeout.")
  }

  private fun ensureAuthorizedVpn() {
    val prepared =
        try {
          VpnService.prepare(context) == null
        } catch (_: Exception) {
          false
        }
    if (!prepared) {
      throw IllegalStateException("VPN permission is not already authorized.")
    }
    runOnMain { UninitializedApp.get().startVPN() }

    val deadline = SystemClock.elapsedRealtime() + VPN_START_TIMEOUT_MS
    while (SystemClock.elapsedRealtime() < deadline) {
      if (isVpnActive() && safeBackendIsRunning()) return
      SystemClock.sleep(VPN_STATUS_POLL_INTERVAL_MS)
    }
    throw IllegalStateException("Authorized Tailscale VPN did not become active and Running.")
  }

  private fun safeBackendIsRunning(): Boolean {
    return try {
      localApiJson("GET", "status").jsonObject.stringValue("BackendState") == STATE_RUNNING
    } catch (_: Exception) {
      false
    }
  }

  private fun localApiJson(
      method: String,
      endpoint: String,
      body: JsonElement? = null,
  ): JsonElement {
    val response =
        try {
          libtailscaleApp.callLocalAPI(
              LOCAL_API_TIMEOUT_MS,
              method,
              "/localapi/v0/$endpoint",
              body?.let {
                InputStreamAdapter(it.toString().byteInputStream(StandardCharsets.UTF_8))
              },
          )
        } catch (_: Exception) {
          throw IllegalStateException("LocalAPI request failed.")
        }
    val statusCode = response.statusCode()
    val responseBytes =
        try {
          response.bodyBytes() ?: ByteArray(0)
        } catch (_: Exception) {
          throw IllegalStateException("LocalAPI response could not be read.")
        }
    if (statusCode !in 200..299) {
      throw IllegalStateException("LocalAPI request failed with HTTP $statusCode.")
    }
    if (responseBytes.isEmpty()) return JsonObject(emptyMap())
    return try {
      Json.parseToJsonElement(String(responseBytes, StandardCharsets.UTF_8))
    } catch (_: Exception) {
      throw IllegalStateException("LocalAPI returned invalid JSON.")
    }
  }

  private fun readAndDeleteAuthKey(): String {
    return readAndDeleteFile(AUTH_KEY_FILENAME, "Regression auth key is unavailable.")
        .trim()
        .takeIf { it.isNotEmpty() }
        ?: throw IllegalStateException("Regression auth key is unavailable.")
  }

  private fun patchAndVerifyHostname(includeLoginPrefs: Boolean): JsonObject {
    val patchedPrefs =
        localApiJson(
                "PATCH",
                "prefs",
                buildJsonObject {
                  put("Hostname", REGRESSION_HOSTNAME)
                  put("HostnameSet", true)
                  if (includeLoginPrefs) {
                    put("LoggedOut", false)
                    put("LoggedOutSet", true)
                  }
                },
            )
            .jsonObject
    if (patchedPrefs.stringValue("Hostname") != REGRESSION_HOSTNAME) {
      throw IllegalStateException("Regression hostname could not be verified.")
    }
    return patchedPrefs
  }

  private fun readAndDeleteFile(name: String, failureMessage: String): String {
    val file = File(context.cacheDir, name)
    var bytes: ByteArray? = null
    try {
      val contents = file.readBytes()
      bytes = contents
      if (!file.delete() && file.exists()) {
        throw IllegalStateException(failureMessage)
      }
      return String(contents, StandardCharsets.UTF_8)
    } catch (_: Exception) {
      throw IllegalStateException(failureMessage)
    } finally {
      bytes?.fill(0)
      file.delete()
    }
  }

  private fun runOnMain(action: () -> Unit) {
    try {
      instrumentation.runOnMainSync(action)
    } catch (_: Exception) {
      throw IllegalStateException("Regression client operation failed.")
    }
  }

  private fun isOperation(expected: String): Boolean {
    return InstrumentationRegistry.getArguments().getString(ARG_OPERATION) == expected
  }

  private fun JsonObject.stringValue(key: String): String {
    return this[key]?.jsonPrimitive?.contentOrNull.orEmpty()
  }

  private fun JsonObject.booleanValue(key: String): Boolean {
    return this[key]?.jsonPrimitive?.contentOrNull == "true"
  }

  private fun JsonObject.objectValue(key: String): JsonObject? {
    return this[key] as? JsonObject
  }

  private fun JsonObject.arrayValue(key: String): JsonArray {
    return this[key] as? JsonArray ?: JsonArray(emptyList())
  }

  private fun JsonArray.stringValues(): List<String> {
    return mapNotNull { it.jsonPrimitive.contentOrNull }
  }

  private companion object {
    const val ARG_OPERATION = "regressionOperation"
    const val OP_REGISTER = "register"
    const val OP_STATUS = "status"
    const val OP_APPLY = "apply"
    const val OP_DISABLE = "disable"
    const val OP_SELECT_EXIT = "selectexit"
    const val OP_CLEAR_EXIT = "clearexit"
    const val OP_CONTROL_PROBE = "controlprobe"
    const val ARG_EXIT_NODE_ID = "exitNodeId"
    const val AUTH_KEY_FILENAME = "regression-authkey"
    const val REGRESSION_HOSTNAME = "regression-tailsing-test"
    const val CONTROL_PLANE_KEY_URL = "https://controlplane.tailscale.com/key"
    const val STATE_NEEDS_LOGIN = "NeedsLogin"
    const val STATE_RUNNING = "Running"
    const val LOCAL_API_TIMEOUT_MS = 10_000L
    const val REGISTRATION_TIMEOUT_MS = 60_000L
    const val STATUS_POLL_INTERVAL_MS = 1_000L
    const val HEALTH_DNS = "dns"
    const val HEALTH_TLS = "tls"
    const val HEALTH_TIMEOUT = "timeout"
    const val HEALTH_CONTROL = "control"
    const val HEALTH_AUTH = "auth"
    const val HEALTH_AUTH_KEY_INVALID = "auth_key_invalid"
    const val HEALTH_AUTH_KEY_EXPIRED = "auth_key_expired"
    const val HEALTH_AUTH_KEY_USED = "auth_key_used"
    const val HEALTH_NETWORK = "network"
    const val HEALTH_OTHER = "other"
    const val CONTROL_ERROR_DNS = "dns"
    const val CONTROL_ERROR_TIMEOUT = "timeout"
    const val CONTROL_ERROR_TLS = "tls"
    const val CONTROL_ERROR_CONNECT = "connect"
    const val CONTROL_ERROR_OTHER = "other"
    const val STAGE_PREFS_VERIFIED = "prefs_verified"
    const val STAGE_START_ACCEPTED = "start_accepted"
    const val STAGE_LOGIN_REQUESTED = "login_requested"
    const val STAGE_VPN_REQUESTED = "vpn_requested"
    const val CONTROL_PROBE_TIMEOUT_MS = 5_000
    const val VPN_START_TIMEOUT_MS = 30_000L
    const val VPN_STATUS_POLL_INTERVAL_MS = 500L
  }
}
