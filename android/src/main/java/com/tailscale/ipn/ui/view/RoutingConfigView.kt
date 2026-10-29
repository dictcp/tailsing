// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package com.tailscale.ipn.ui.view

import android.content.Context
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.tailscale.ipn.App
import com.tailscale.ipn.R
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private const val routingDraftPreferences = "sing_box_routing"
private const val routingDraftKey = "draft_json"

private fun safeRoutingError(error: Throwable, context: Context): String {
  val message = error.message ?: return context.getString(R.string.routing_config_operation_failed)
  val jsonSecret =
      Regex("""(?i)("(?:password|token|secret|auth_key|private_key|uuid)"\s*:\s*")[^"]*(")""")
  val urlCredentials = Regex("""(?i)([a-z][a-z0-9+.-]*://)[^/@\s]+@""")
  return urlCredentials.replace(jsonSecret.replace(message, "$1[redacted]$2"), "$1[redacted]@")
}

@Composable
fun RoutingConfigView(backToSettings: BackNavigation) {
  val context = LocalContext.current
  val scope = rememberCoroutineScope()
  val app = remember { App.get().getLibtailscaleApp() }
  val preferences =
      remember(context) {
        context.getSharedPreferences(routingDraftPreferences, Context.MODE_PRIVATE)
      }

  var config by remember { mutableStateOf(preferences.getString(routingDraftKey, "") ?: "") }
  var status by remember { mutableStateOf("") }
  var message by remember { mutableStateOf("") }
  var isError by remember { mutableStateOf(false) }
  var isBusy by remember { mutableStateOf(false) }
  var showDisableConfirm by remember { mutableStateOf(false) }

  LaunchedEffect(config) {
    delay(400)
    preferences.edit().putString(routingDraftKey, config).apply()
  }

  LaunchedEffect(app) {
    try {
      val (activeConfig, activeStatus) =
          withContext(Dispatchers.IO) { app.routingConfig() to app.routingStatus() }
      if (config.isBlank()) config = activeConfig
      status = activeStatus
    } catch (error: Throwable) {
      if (error is CancellationException) throw error
      // Configuration and credentials are never logged. Redact common secret
      // forms before displaying validation/runtime messages.
      message = safeRoutingError(error, context)
      isError = true
    }
  }

  fun runOperation(successMessage: String, operation: () -> Unit) {
    if (isBusy) return
    isBusy = true
    message = ""
    isError = false
    scope.launch {
      try {
        withContext(Dispatchers.IO) { operation() }
        message = successMessage
        status = withContext(Dispatchers.IO) { app.routingStatus() }
      } catch (error: Throwable) {
        if (error is CancellationException) throw error
        message = safeRoutingError(error, context)
        isError = true
        // Apply can fail after capture enters the blocked state. Refresh the
        // status without hiding the original validation or activation error.
        try {
          status = withContext(Dispatchers.IO) { app.routingStatus() }
        } catch (statusError: Throwable) {
          if (statusError is CancellationException) throw statusError
          status = ""
        }
      } finally {
        isBusy = false
      }
    }
  }

  Scaffold(topBar = { Header(R.string.routing_config_title, onBack = backToSettings) }) {
      innerPadding ->
    Column(
        modifier =
            Modifier.fillMaxWidth()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
      Text(stringResource(R.string.routing_config_description))
      if (status.isNotBlank()) {
        Text(
            text = stringResource(R.string.routing_config_status, status),
            style = MaterialTheme.typography.bodyMedium,
        )
      }
      OutlinedTextField(
          value = config,
          onValueChange = {
            config = it
            isError = false
          },
          modifier = Modifier.fillMaxWidth().heightIn(min = 360.dp, max = 620.dp),
          label = { Text(stringResource(R.string.routing_config_json_label)) },
          textStyle = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
          keyboardOptions =
              KeyboardOptions(
                  capitalization = KeyboardCapitalization.None,
                  autoCorrectEnabled = false,
                  keyboardType = KeyboardType.Ascii,
              ),
          enabled = !isBusy,
          minLines = 18,
      )

      Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        OutlinedButton(
            onClick = {
              runOperation(context.getString(R.string.routing_config_valid)) {
                app.validateRoutingConfig(config)
              }
            },
            enabled = !isBusy && config.isNotBlank(),
        ) {
          Text(stringResource(R.string.routing_config_validate))
        }
        Button(
            onClick = {
              runOperation(context.getString(R.string.routing_config_applied)) {
                app.applyRoutingConfig(config)
              }
            },
            enabled = !isBusy && config.isNotBlank(),
        ) {
          Text(stringResource(R.string.routing_config_apply))
        }
      }

      OutlinedButton(
          onClick = { showDisableConfirm = true },
          enabled = !isBusy,
      ) {
        Text(stringResource(R.string.routing_config_disable))
      }

      if (isBusy) CircularProgressIndicator()
      if (message.isNotBlank()) {
        Text(
            text = message,
            color =
                if (isError) MaterialTheme.colorScheme.error
                else MaterialTheme.colorScheme.onSurfaceVariant,
            style = MaterialTheme.typography.bodySmall,
        )
      }
    }
  }

  if (showDisableConfirm) {
    AlertDialog(
        onDismissRequest = { showDisableConfirm = false },
        title = { Text(stringResource(R.string.routing_config_disable_confirm_title)) },
        text = { Text(stringResource(R.string.routing_config_disable_confirm_message)) },
        confirmButton = {
          TextButton(
              enabled = !isBusy,
              onClick = {
                showDisableConfirm = false
                runOperation(context.getString(R.string.routing_config_disabled)) {
                  app.disableRouting()
                }
              },
          ) {
            Text(stringResource(R.string.routing_config_disable))
          }
        },
        dismissButton = {
          TextButton(onClick = { showDisableConfirm = false }, enabled = !isBusy) {
            Text(stringResource(R.string.cancel))
          }
        },
    )
  }
}
