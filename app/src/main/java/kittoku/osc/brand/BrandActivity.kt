package kittoku.osc.brand

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.content.ClipboardManager
import android.net.Uri
import android.view.Menu
import android.view.MenuItem
import android.animation.ObjectAnimator
import android.animation.PropertyValuesHolder
import android.animation.ValueAnimator
import android.view.View
import android.view.animation.LinearInterpolator
import androidx.core.content.ContextCompat
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.IntentCompat
import androidx.preference.PreferenceManager
import kittoku.osc.R
import kittoku.osc.databinding.ActivityBrandBinding
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.service.ACTION_VPN_CONNECT
import kittoku.osc.service.ACTION_VPN_DISCONNECT
import kittoku.osc.service.SstpVpnService
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors


private const val PREF_ASKED_BATTERY = "BRAND_ASKED_BATTERY"

class BrandActivity : AppCompatActivity() {
    private lateinit var binding: ActivityBrandBinding
    private lateinit var prefs: SharedPreferences
    private val io: ExecutorService = Executors.newSingleThreadExecutor()

    private var config: AppConfig? = null
    private var statusLoading = false
    private var lastStatusFetch = 0L
    private var wasConnected = false
    private var ringAnim: ObjectAnimator? = null
    private var haloAnim: ObjectAnimator? = null
    private var updateFile: java.io.File? = null
    private var updateDownloading = false
    private var installAfterPermission = false
    private val downloader: ExecutorService = Executors.newSingleThreadExecutor()

    private enum class Conn { DISCONNECTED, CONNECTING, CONNECTED }

    private val prefListener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
        if (key == OscPrefKey.ROOT_STATE.name || key == OscPrefKey.HOME_STATUS.name ||
            key == BrandSession.PREF_LAST_ERROR) {
            runOnUiThread { renderConnection() }
        }
    }

    private val vpnPermission = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpn(ACTION_VPN_CONNECT)
        } else if (android.os.SystemClock.elapsedRealtime() - vpnAskedAt < 1500 || Tv.isTv(this)) {
            // answered before anyone could press anything: this device (often a TV) has no
            // VPN permission window at all
            showConnError(getString(R.string.brand_vpn_denied))
            showNoVpnDialogHelp()
        } else {
            showConnError(getString(R.string.brand_vpn_denied))
        }
    }

    private var vpnAskedAt = 0L

    private fun askVpnPermission(intent: Intent) {
        vpnAskedAt = android.os.SystemClock.elapsedRealtime()
        try {
            vpnPermission.launch(intent)
        } catch (_: android.content.ActivityNotFoundException) {
            showConnError(getString(R.string.brand_vpn_denied))
            showNoVpnDialogHelp()
        }
    }

    private fun showNoVpnDialogHelp() {
        AlertDialog.Builder(this)
            .setTitle(R.string.brand_vpn_nodialog_title)
            .setMessage(getString(R.string.brand_vpn_nodialog_text, packageName))
            .setPositiveButton(R.string.brand_ok, null)
            .show()
    }

    private val pickConfigFile = registerForActivityResult(
        ActivityResultContracts.OpenDocument()
    ) { uri -> uri?.let { importFromUri(it) } }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityBrandBinding.inflate(layoutInflater)
        binding.root.fitsSystemWindows = true
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        title = getString(R.string.app_name)
        Tv.centre(binding.brandContent)
        if (Tv.isTv(this)) binding.shareButton.visibility = View.GONE     // no hotspot on a TV

        prefs = PreferenceManager.getDefaultSharedPreferences(this)

        config = try {
            ConfigManager.current(this)
        } catch (e: Exception) {
            // Only happens with a broken build (assets missing or signed with another key).
            AlertDialog.Builder(this)
                .setMessage("Build error: ${e.message}")
                .setCancelable(false)
                .setPositiveButton("OK") { _, _ -> finish() }
                .show()
            null
        }

        binding.loginButton.setOnClickListener { onLoginClicked() }
        binding.connectButton.setOnClickListener { onConnectClicked() }
        binding.refreshButton.setOnClickListener { refreshStatus(force = true) }
        binding.logoutButton.setOnClickListener { onLogoutClicked() }
        binding.updateButton.setOnClickListener { onUpdateClicked() }
        binding.shareButton.setOnClickListener {
            startActivity(Intent(this, ShareActivity::class.java))
        }
        binding.shieldButton.setOnClickListener {
            startActivity(Intent(this, ExcludedAppsActivity::class.java)
                .putExtra(ExcludedAppsActivity.EXTRA_SHIELD, true))
        }
        binding.excludedButton.setOnClickListener {
            startActivity(Intent(this, ExcludedAppsActivity::class.java))
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1)
        }

        // Pick up a newer signed server list in the background.
        if (config != null) {
            io.execute {
                if (ConfigManager.refresh(applicationContext)) {
                    val fresh = ConfigManager.current(applicationContext)
                    runOnUiThread {
                        config = fresh
                        renderUpdate()
                    }
                }
            }
        }

        render()
        handleIncoming(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIncoming(intent)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.brand_menu, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.brand_import_config) {
            showImportDialog()
            return true
        }
        if (item.itemId == R.id.brand_last_error) {
            showLastErrorReport()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    override fun onStart() {
        super.onStart()
        prefs.registerOnSharedPreferenceChangeListener(prefListener)
        renderConnection()
    }

    override fun onResume() {
        super.onResume()
        // back from the "install unknown apps" setting
        if (installAfterPermission) {
            installAfterPermission = false
            updateFile?.let { startInstall(it) }
        }
        binding.shareButton.setText(if (BrandSession.shareEnabled(prefs)) R.string.brand_share_button_on
                                     else R.string.brand_share_button)
        val ns = BrandSession.shieldedApps(prefs).size
        binding.shieldButton.text = if (ns == 0) getString(R.string.brand_shield_button)
            else getString(R.string.brand_shield_button_count, Fa.digits(ns.toString()))
        val n = BrandSession.excludedApps(prefs).size
        binding.excludedButton.text = if (n == 0) getString(R.string.brand_excluded_button)
            else getString(R.string.brand_excluded_button_count, Fa.digits(n.toString()))
        if (BrandSession.isLoggedIn(prefs)) refreshStatus(force = false)
    }

    override fun onStop() {
        stopButtonAnimations()
        prefs.unregisterOnSharedPreferenceChangeListener(prefListener)
        super.onStop()
    }

    override fun onDestroy() {
        downloader.shutdown()
        io.shutdown()
        super.onDestroy()
    }

    // ------------------------------------------------------------ screens

    private fun render() {
        renderUpdate()
        val loggedIn = BrandSession.isLoggedIn(prefs)
        binding.loginGroup.visibility = if (loggedIn) View.GONE else View.VISIBLE
        binding.mainGroup.visibility = if (loggedIn) View.VISIBLE else View.GONE

        if (Tv.isTv(this)) {                 // the remote starts on what matters
            (if (loggedIn) binding.connectButton else binding.usernameInput).post {
                if (currentFocus == null || currentFocus === binding.toolbar) {
                    (if (loggedIn) binding.connectButton else binding.usernameInput).requestFocus()
                }
            }
        }
        if (loggedIn) {
            binding.accountName.text = getString(R.string.brand_account_of, "\u2068" + BrandSession.username(prefs) + "\u2069")
            renderConnection()
            BrandSession.savedStatus(prefs)?.let { renderStatus(it) }
        } else {
            binding.usernameInput.setText(BrandSession.username(prefs))
        }
    }

    // ------------------------------------------------------------ login

    private fun onLoginClicked() {
        val cfg = config ?: return
        val user = binding.usernameInput.text?.toString()?.trim().orEmpty()
        val pass = binding.passwordInput.text?.toString().orEmpty()
        if (user.isEmpty() || pass.isEmpty()) {
            showLoginMessage(getString(R.string.brand_err_fill))
            return
        }

        setLoginBusy(true)
        io.execute {
            val result = StatusClient.fetch(cfg, user, pass)
            runOnUiThread {
                setLoginBusy(false)
                when (result) {
                    is StatusResult.Ok -> {
                        BrandSession.login(prefs, user, pass)
                        BrandSession.saveStatus(prefs, result.status)
                        lastStatusFetch = SystemClock.elapsedRealtime()
                        binding.passwordInput.setText("")
                        render()
                    }
                    StatusResult.InvalidCredentials ->
                        showLoginMessage(getString(R.string.brand_err_credentials))
                    StatusResult.TooManyAttempts ->
                        showLoginMessage(getString(R.string.brand_err_too_many))
                    StatusResult.ServerProblem, StatusResult.Unreachable -> {
                        // The status service may be filtered while the VPN still
                        // works: let the user in and let the router decide.
                        BrandSession.login(prefs, user, pass)
                        binding.passwordInput.setText("")
                        Toast.makeText(this, R.string.brand_login_offline, Toast.LENGTH_LONG).show()
                        render()
                    }
                }
            }
        }
    }

    private fun setLoginBusy(busy: Boolean) {
        binding.loginButton.isEnabled = !busy
        binding.loginProgress.visibility = if (busy) View.VISIBLE else View.GONE
        if (busy) binding.loginMessage.visibility = View.GONE
    }

    private fun showLoginMessage(text: String) {
        binding.loginMessage.text = text
        binding.loginMessage.visibility = View.VISIBLE
    }

    private fun onLogoutClicked() {
        AlertDialog.Builder(this)
            .setMessage(R.string.brand_logout_confirm)
            .setPositiveButton(R.string.brand_yes) { _, _ ->
                if (connectionState() != Conn.DISCONNECTED) startVpn(ACTION_VPN_DISCONNECT)
                BrandSession.logout(prefs)
                render()
            }
            .setNegativeButton(R.string.brand_no, null)
            .show()
    }

    // ------------------------------------------------------------ VPN

    private fun connectionState(): Conn {
        val running = getBooleanPrefValue(OscPrefKey.ROOT_STATE, prefs)
        val established = getStringPrefValue(OscPrefKey.HOME_STATUS, prefs).isNotEmpty()
        return when {
            !running -> Conn.DISCONNECTED
            established -> Conn.CONNECTED
            else -> Conn.CONNECTING
        }
    }

    private fun renderConnection() {
        if (!::binding.isInitialized || !BrandSession.isLoggedIn(prefs)) return

        val state = connectionState()
        styleConnectButton(state)

        val err = BrandSession.lastError(prefs)
        // while reconnecting, an old error would only confuse
        if (state == Conn.DISCONNECTED && err != null) {
            showConnError(describeEngineError(err))
        } else {
            binding.connError.visibility = View.GONE
        }

        // Usage changes while connected; refresh once the tunnel is up.
        if (state == Conn.CONNECTED && !wasConnected) {
            refreshStatus(force = true)
            askBatteryExemptionOnce()
        }
        wasConnected = state == Conn.CONNECTED
    }

    /** Power button look per state; the animations run only while visible. */
    private fun styleConnectButton(state: Conn) {
        val (stateText, color, hint) = when (state) {
            Conn.DISCONNECTED -> Triple(R.string.brand_state_disconnected, R.color.brand_text, R.string.brand_hint_connect)
            Conn.CONNECTING -> Triple(R.string.brand_state_connecting, R.color.brand_warn, R.string.brand_hint_cancel)
            Conn.CONNECTED -> Triple(R.string.brand_state_connected, R.color.brand_accent, R.string.brand_hint_disconnect)
        }
        binding.connState.setText(stateText)
        binding.connState.setTextColor(ContextCompat.getColor(this, color))
        binding.connHint.setText(hint)
        binding.connectButton.contentDescription = getString(
            if (state == Conn.DISCONNECTED) R.string.brand_connect else R.string.brand_disconnect)

        val on = state == Conn.CONNECTED
        binding.connectCircle.setBackgroundResource(if (on) R.drawable.brand_btn_on else R.drawable.brand_btn_off)
        binding.connectIcon.setColorFilter(ContextCompat.getColor(this,
            if (on) R.color.brand_on_accent else R.color.brand_text))

        // spinning ring while connecting
        if (state == Conn.CONNECTING) {
            binding.connectRing.visibility = View.VISIBLE
            if (ringAnim == null) {
                ringAnim = ObjectAnimator.ofFloat(binding.connectRing, View.ROTATION, 0f, 360f).apply {
                    duration = 1100
                    repeatCount = ValueAnimator.INFINITE
                    interpolator = LinearInterpolator()
                    start()
                }
            }
        } else {
            ringAnim?.cancel()
            ringAnim = null
            binding.connectRing.visibility = View.INVISIBLE
        }

        // slow glow pulse while connected
        if (on) {
            binding.connectHalo.visibility = View.VISIBLE
            if (haloAnim == null) {
                haloAnim = ObjectAnimator.ofPropertyValuesHolder(binding.connectHalo,
                    PropertyValuesHolder.ofFloat(View.SCALE_X, 0.88f, 1.0f),
                    PropertyValuesHolder.ofFloat(View.SCALE_Y, 0.88f, 1.0f),
                    PropertyValuesHolder.ofFloat(View.ALPHA, 0.55f, 1.0f)).apply {
                    duration = 1600
                    repeatCount = ValueAnimator.INFINITE
                    repeatMode = ValueAnimator.REVERSE
                    start()
                }
            }
        } else {
            haloAnim?.cancel()
            haloAnim = null
            binding.connectHalo.visibility = View.INVISIBLE
        }
    }

    /**
     * Battery optimization lets Android cut the VPN while the screen is off.
     * Ask once (after the first successful connection) to be exempted.
     */
    private fun askBatteryExemptionOnce() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        val pm = getSystemService(POWER_SERVICE) as android.os.PowerManager
        if (pm.isIgnoringBatteryOptimizations(packageName)) return
        if (prefs.getBoolean(PREF_ASKED_BATTERY, false)) return
        prefs.edit().putBoolean(PREF_ASKED_BATTERY, true).apply()

        AlertDialog.Builder(this)
            .setTitle(R.string.brand_battery_title)
            .setMessage(R.string.brand_battery_message)
            .setPositiveButton(R.string.brand_battery_allow) { _, _ ->
                try {
                    startActivity(Intent(
                        android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
                        Uri.parse("package:$packageName")))
                } catch (_: Exception) {
                    try {   // some TVs have neither screen
                        startActivity(Intent(android.provider.Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                    } catch (_: Exception) {
                    }
                }
            }
            .setNegativeButton(R.string.brand_battery_later, null)
            .show()
    }

    private fun stopButtonAnimations() {
        ringAnim?.cancel()
        ringAnim = null
        haloAnim?.cancel()
        haloAnim = null
    }

    private fun describeEngineError(header: String): String =
        BrandSession.describeError(this, header)

    private fun showConnError(text: String) {
        binding.connError.text = text
        binding.connError.visibility = View.VISIBLE
    }

    private fun onConnectClicked() {
        if (connectionState() != Conn.DISCONNECTED) {
            startVpn(ACTION_VPN_DISCONNECT)
            return
        }

        val cfg = config ?: return
        val server = cfg.servers.firstOrNull() ?: return
        BrandSession.applyEngineSettings(prefs, server)
        binding.connError.visibility = View.GONE

        val intent = VpnService.prepare(this)
        if (intent != null) askVpnPermission(intent) else startVpn(ACTION_VPN_CONNECT)
    }

    private fun startVpn(action: String) {
        val intent = Intent(this, SstpVpnService::class.java).setAction(action)
        if (action == ACTION_VPN_CONNECT && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    // ------------------------------------------------------------ in-app update

    private fun renderUpdate() {
        val upd = UpdateManager.available(config, BrandSession.username(prefs))
        if (upd == null) {
            binding.updateCard.visibility = View.GONE
            return
        }
        binding.updateCard.visibility = View.VISIBLE
        binding.updateTitle.text = getString(R.string.brand_update_title,
            Fa.digits(upd.versionName.ifBlank { upd.versionCode.toString() }))
        val notes = if (UpdateManager.isBeta(upd)) getString(R.string.brand_update_beta) + "\n" + upd.notes
                    else upd.notes
        fun show(bytes: Long) {
            val size = getString(R.string.brand_update_size,
                Fa.digits(String.format(java.util.Locale.US, "%.1f", bytes / 1_048_576.0)))
            binding.updateNotes.text = if (notes.isBlank()) size else "${notes.trim()}\n$size"
        }
        show(upd.size)
        if (upd.patches.isNotEmpty()) {
            // the patch from this phone's version is usually much smaller
            val app = applicationContext
            io.execute {
                val bytes = UpdateManager.downloadSize(app, upd)
                runOnUiThread {
                    if (UpdateManager.available(config, BrandSession.username(prefs)) == upd) show(bytes)
                }
            }
        }
        if (!updateDownloading) {
            binding.updateButton.setText(
                if (updateFile != null) R.string.brand_update_install else R.string.brand_update_button)
        }
    }

    private fun onUpdateClicked() {
        val upd = UpdateManager.available(config, BrandSession.username(prefs)) ?: return
        updateFile?.let { startInstall(it); return }
        if (updateDownloading) return

        updateDownloading = true
        binding.updateButton.isEnabled = false
        binding.updateProgress.visibility = View.VISIBLE
        binding.updateProgress.progress = 0
        binding.updateStatus.visibility = View.VISIBLE
        binding.updateStatus.text = getString(R.string.brand_update_downloading, Fa.digits("0"))

        val pins = config?.configPins ?: emptyList()
        downloader.execute {
            val outcome: Any = try {
                UpdateManager.download(applicationContext, upd, pins) { pct ->
                    runOnUiThread {
                        binding.updateProgress.progress = pct
                        binding.updateStatus.text =
                            getString(R.string.brand_update_downloading, Fa.digits(pct.toString()))
                    }
                }
            } catch (e: UpdateManager.UpdateException) {
                e.reason
            } catch (e: Exception) {
                UpdateManager.Reason.NETWORK
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                updateDownloading = false
                binding.updateButton.isEnabled = true
                binding.updateProgress.visibility = View.GONE
                when (outcome) {
                    is java.io.File -> {
                        updateFile = outcome
                        binding.updateStatus.setText(R.string.brand_update_ready)
                        binding.updateButton.setText(R.string.brand_update_install)
                        startInstall(outcome)
                    }
                    UpdateManager.Reason.BAD_FILE ->
                        binding.updateStatus.setText(R.string.brand_update_err_file)
                    else ->
                        binding.updateStatus.setText(R.string.brand_update_err_network)
                }
            }
        }
    }

    private fun startInstall(apk: java.io.File) {
        if (!apk.isFile) {
            updateFile = null
            renderUpdate()
            return
        }
        try {
            if (UpdateManager.install(this, apk) == UpdateManager.InstallStep.NEEDS_PERMISSION) {
                installAfterPermission = true
                Toast.makeText(this, R.string.brand_update_permission, Toast.LENGTH_LONG).show()
            }
        } catch (e: Exception) {
            binding.updateStatus.visibility = View.VISIBLE
            binding.updateStatus.setText(R.string.brand_update_err_file)
        }
    }

    // ------------------------------------------------------------ manual config import

    /** A config file opened or shared from another app (e.g. Telegram). */
    private fun handleIncoming(intent: Intent?) {
        if (intent == null || config == null) return
        when (intent.action) {
            Intent.ACTION_VIEW -> intent.data?.let { importFromUri(it) }
            Intent.ACTION_SEND -> {
                val stream = IntentCompat.getParcelableExtra(intent, Intent.EXTRA_STREAM, Uri::class.java)
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                when {
                    stream != null -> importFromUri(stream)
                    !text.isNullOrBlank() -> importText(text)
                }
            }
            else -> return
        }
        // do not import the same file again on rotation
        setIntent(Intent(this, BrandActivity::class.java))
    }

    private fun showLastErrorReport() {
        val text = BrandSession.errorDetail(prefs)
        val b = AlertDialog.Builder(this).setTitle(R.string.brand_last_error_title)
        if (text == null) {
            b.setMessage(R.string.brand_last_error_none).setPositiveButton(R.string.brand_ok, null).show()
            return
        }
        b.setMessage(text)
            .setPositiveButton(R.string.brand_copy) { _, _ ->
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(android.content.ClipData.newPlainText("error report", text))
                Toast.makeText(this, R.string.brand_copied, Toast.LENGTH_SHORT).show()
            }
            .setNegativeButton(R.string.brand_ok, null)
            .show()
    }

    private fun showImportDialog() {
        AlertDialog.Builder(this)
            .setTitle(R.string.brand_import_title)
            .setMessage(R.string.brand_import_help)
            .setPositiveButton(R.string.brand_import_file) { _, _ ->
                pickConfigFile.launch(arrayOf("*/*"))
            }
            .setNeutralButton(R.string.brand_import_clipboard) { _, _ ->
                val cm = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
                val text = cm.primaryClip?.takeIf { it.itemCount > 0 }
                    ?.getItemAt(0)?.coerceToText(this)?.toString()
                if (text.isNullOrBlank()) {
                    Toast.makeText(this, R.string.brand_import_empty, Toast.LENGTH_SHORT).show()
                } else {
                    importText(text)
                }
            }
            .setNegativeButton(R.string.brand_cancel, null)
            .show()
    }

    private fun importFromUri(uri: Uri) {
        io.execute {
            val text = try {
                contentResolver.openInputStream(uri)?.use { stream ->
                    val bytes = stream.readBytes()
                    if (bytes.size > 64 * 1024) null else String(bytes, Charsets.UTF_8)
                }
            } catch (e: Exception) {
                null
            }
            if (text == null) {
                runOnUiThread { showImportResult(ConfigManager.InstallResult.INVALID, null) }
            } else {
                importTextBlocking(text)
            }
        }
    }

    private fun importText(text: String) {
        io.execute { importTextBlocking(text) }
    }

    private fun importTextBlocking(text: String) {
        val (result, cfg) = ConfigManager.install(applicationContext, text)
        runOnUiThread {
            if (result == ConfigManager.InstallResult.INSTALLED && cfg != null) {
                config = cfg
                renderUpdate()
            }
            showImportResult(result, cfg)
        }
    }

    private fun showImportResult(result: ConfigManager.InstallResult, cfg: AppConfig?) {
        val msg = when (result) {
            ConfigManager.InstallResult.INSTALLED -> {
                var m = getString(R.string.brand_import_ok, Fa.digits(cfg?.version.toString()))
                if (connectionState() != Conn.DISCONNECTED) {
                    m += "\n" + getString(R.string.brand_import_reconnect)
                }
                m
            }
            ConfigManager.InstallResult.NOT_NEWER ->
                getString(R.string.brand_import_not_newer, Fa.digits(cfg?.version.toString()))
            ConfigManager.InstallResult.INVALID -> getString(R.string.brand_import_invalid)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.brand_import_title)
            .setMessage(msg)
            .setPositiveButton(R.string.brand_ok, null)
            .show()

        if (result == ConfigManager.InstallResult.INSTALLED && BrandSession.isLoggedIn(prefs)) {
            refreshStatus(force = true)
        }
    }

    // ------------------------------------------------------------ account status

    private fun refreshStatus(force: Boolean) {
        val cfg = config ?: return
        if (statusLoading) return
        val now = SystemClock.elapsedRealtime()
        if (!force && lastStatusFetch != 0L && now - lastStatusFetch < 60_000) return

        val user = BrandSession.username(prefs)
        val pass = BrandSession.password(prefs)
        if (user.isEmpty()) return

        statusLoading = true
        binding.statusProgress.visibility = View.VISIBLE
        binding.refreshButton.isEnabled = false

        io.execute {
            val result = StatusClient.fetch(cfg, user, pass)
            runOnUiThread {
                statusLoading = false
                binding.statusProgress.visibility = View.GONE
                binding.refreshButton.isEnabled = true
                if (!BrandSession.isLoggedIn(prefs)) return@runOnUiThread

                when (result) {
                    is StatusResult.Ok -> {
                        lastStatusFetch = SystemClock.elapsedRealtime()
                        BrandSession.saveStatus(prefs, result.status)
                        renderStatus(result.status)
                    }
                    StatusResult.InvalidCredentials ->
                        showStatusMessage(getString(R.string.brand_err_credentials))
                    StatusResult.TooManyAttempts ->
                        showStatusMessage(getString(R.string.brand_err_too_many))
                    StatusResult.ServerProblem, StatusResult.Unreachable -> {
                        showStatusMessage(getString(
                            if (BrandSession.savedStatus(prefs) != null) R.string.brand_err_status_offline
                            else R.string.brand_err_unreachable))
                    }
                }
            }
        }
    }

    private fun showStatusMessage(text: String) {
        binding.statusMessage.text = text
        binding.statusMessage.visibility = View.VISIBLE
    }

    private fun renderStatus(st: AccountStatus) {
        binding.statusMessage.visibility = View.GONE
        val cur = st.current

        binding.planName.text = cur?.display?.takeIf { it.isNotBlank() }
            ?.let { "${getString(R.string.brand_account)}: ${Fa.digits(it)}" }
            ?: getString(R.string.brand_account)

        binding.usedText.visibility = View.GONE
        if (cur == null) {
            binding.daysText.text = "—"
            binding.remainingValue.text = "—"
            binding.remainingText.text = ""
            binding.endText.text = ""
            binding.usageBar.visibility = View.GONE
        } else {
            val days = cur.daysLeft
            binding.daysText.text = when {
                days == null -> "—"
                days >= 1 -> Fa.digits(days.toString())
                (cur.secondsLeft ?: 0L) > 0L -> "<" + Fa.digits("1")
                else -> Fa.digits("0")
            }

            val limit = cur.limitBytes
            val remaining = cur.remainingBytes
            if (limit != null && limit > 0 && remaining != null) {
                binding.remainingValue.text = Fa.gb(remaining)
                binding.remainingText.text =
                    getString(R.string.brand_used_of, Fa.gb(cur.usedBytes), Fa.gb(limit))
                binding.usageBar.visibility = View.VISIBLE
                binding.usageBar.progress = ((remaining.toDouble() / limit) * 1000).toInt().coerceIn(0, 1000)
                // amber bar when less than 10 % is left
                binding.usageBar.setIndicatorColor(ContextCompat.getColor(this,
                    if (remaining * 10 < limit) R.color.brand_warn else R.color.brand_accent))
            } else {
                binding.remainingValue.text = "∞"
                binding.remainingText.text = getString(R.string.brand_used, Fa.gb(cur.usedBytes))
                binding.usageBar.visibility = View.GONE
            }
            binding.endText.text = Fa.dateTime(cur.end)?.let { getString(R.string.brand_ends_at, it) } ?: ""
        }

        val next = st.next.firstOrNull()
        if (next != null) {
            binding.nextText.text = getString(R.string.brand_next,
                Fa.digits(next.display.ifBlank { next.profile }))
            binding.nextText.visibility = View.VISIBLE
        } else {
            binding.nextText.visibility = View.GONE
        }

        val notice = when {
            st.disabled -> R.string.brand_st_disabled
            st.state == "expired" -> R.string.brand_st_expired
            st.state == "volume_finished" -> R.string.brand_st_volume
            st.state == "waiting" -> R.string.brand_st_waiting
            st.state == "no_profile" -> R.string.brand_st_no_profile
            else -> null
        }
        if (notice != null) showStatusMessage(getString(notice))

        binding.updatedText.text = Fa.dateTime(st.serverTime)
            ?.let { getString(R.string.brand_updated_at, it) } ?: ""
    }
}
