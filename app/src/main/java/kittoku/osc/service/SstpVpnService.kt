package kittoku.osc.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.TileService
import androidx.core.app.ActivityCompat
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.documentfile.provider.DocumentFile
import androidx.preference.PreferenceManager
import kittoku.osc.R
import kittoku.osc.SharedBridge
import kittoku.osc.brand.BrandSession
import kittoku.osc.control.Controller
import kittoku.osc.control.LogWriter
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getBooleanPrefValue
import kittoku.osc.preference.accessor.getIntPrefValue
import kittoku.osc.preference.accessor.getURIPrefValue
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.preference.accessor.resetReconnectionLife
import kittoku.osc.preference.accessor.setBooleanPrefValue
import kittoku.osc.preference.accessor.setIntPrefValue
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale


internal const val ACTION_VPN_CONNECT = "kittoku.osc.connect"
internal const val ACTION_VPN_DISCONNECT = "kittoku.osc.disconnect"
internal const val ACTION_VPN_SHIELD = "kittoku.osc.shield"

internal const val NOTIFICATION_ERROR_CHANNEL = "ERROR"
internal const val NOTIFICATION_RECONNECT_CHANNEL = "RECONNECT"
internal const val NOTIFICATION_DISCONNECT_CHANNEL = "DISCONNECT"
internal const val NOTIFICATION_CERTIFICATE_CHANNEL = "CERTIFICATE"

internal const val NOTIFICATION_ERROR_ID = 1
internal const val NOTIFICATION_RECONNECT_ID = 2
internal const val NOTIFICATION_DISCONNECT_ID = 3
internal const val NOTIFICATION_CERTIFICATE_ID = 4


private const val LINUX_RETURN_EVERY_MS = 5 * 60_000L   // on SSTP: how often Linux is tried again

class SstpVpnService : VpnService() {
    private lateinit var prefs: SharedPreferences
    private lateinit var listener: SharedPreferences.OnSharedPreferenceChangeListener
    private lateinit var notificationManager: NotificationManagerCompat
    internal lateinit var scope: CoroutineScope

    internal var logWriter: LogWriter? = null
    private var controller: Controller?  = null

    private var jobReconnect: Job? = null
    private var jobConnect: Job? = null
    private var jobLinuxReturn: Job? = null
    private var linuxTunnel: LinuxTunnel? = null

    private fun setRootState(state: Boolean) {
        setBooleanPrefValue(state, OscPrefKey.ROOT_STATE, prefs)
    }

    private fun requestTileListening() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            TileService.requestListeningState(this,
                ComponentName(this, SstpTileService::class.java)
            )
        }
    }

    override fun onCreate() {
        notificationManager = NotificationManagerCompat.from(this)

        prefs = PreferenceManager.getDefaultSharedPreferences(this)

        listener = SharedPreferences.OnSharedPreferenceChangeListener { _, key ->
            if (key == OscPrefKey.ROOT_STATE.name) {
                val newState = getBooleanPrefValue(OscPrefKey.ROOT_STATE, prefs)

                setBooleanPrefValue(newState, OscPrefKey.HOME_CONNECTOR, prefs)
                requestTileListening()
            }
        }

        prefs.registerOnSharedPreferenceChangeListener(listener)

        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    }

    // ---------------------------------------------------------------- «سپر VPN»
    // While the real tunnel is not up, an empty VPN for the shielded apps only:
    // their packets go nowhere. The real tunnel replaces it when it comes up
    // (onTunnelUp), so there is no moment where they reach the internet directly.

    private var shieldPfd: android.os.ParcelFileDescriptor? = null
    private var shieldJob: Job? = null

    private fun shieldApps(): List<String> = BrandSession.shieldedApps(prefs).filter {
        try {
            packageManager.getApplicationInfo(it, 0); true
        } catch (_: Exception) {
            false
        }
    }

    /** True when the shield is up (the service then keeps running). quiet: between two
     *  tunnels (reconnecting), where the state shown and the notification stay as they are. */
    private fun startShield(quiet: Boolean = false): Boolean {
        val apps = shieldApps()
        if (apps.isEmpty() || VpnService.prepare(this) != null) {
            closeShield()
            return false
        }
        val builder = Builder()
        try {
            builder.setSession(getString(R.string.brand_shield_title))
            builder.addAddress("10.255.255.254", 32)
            builder.addRoute("0.0.0.0", 0)
            builder.addAddress("fd00:7076:73::1", 128)
            builder.addRoute("::", 0)
            builder.addDnsServer("10.255.255.253")
            builder.setBlocking(true)
            apps.forEach { builder.addAllowedApplication(it) }
        } catch (e: Exception) {
            logWriter?.write("shield builder: $e")
            closeShield()
            return false
        }
        val pfd = try { builder.establish() } catch (_: Exception) { null }
        if (pfd == null) {
            closeShield()
            return false
        }
        val old = shieldPfd
        shieldPfd = pfd
        shieldJob?.cancel()
        try { old?.close() } catch (_: Exception) { }
        shieldJob = scope.launch {
            val input = java.io.FileInputStream(pfd.fileDescriptor)
            val buf = ByteArray(32 * 1024)
            try {
                while (isActive && input.read(buf) >= 0) { /* dropped */ }
            } catch (_: Exception) { }
        }
        if (!quiet) {
            setRootState(false)
            showShieldNotification(apps.size)
        }
        return true
    }

    private fun closeShield() {
        shieldJob?.cancel()
        shieldJob = null
        try { shieldPfd?.close() } catch (_: Exception) { }
        shieldPfd = null
    }

    /** The real tunnel's interface exists: it carries the shielded apps from now on. */
    internal fun onTunnelUp() {
        closeShield()
    }

    private fun showShieldNotification(count: Int) {
        beForegroundedChannels()
        val open = PendingIntent.getActivity(this, 2,
            Intent(this, kittoku.osc.brand.BrandActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        val n = NotificationCompat.Builder(this, NOTIFICATION_DISCONNECT_CHANNEL)
            .setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            .setContentTitle(getString(R.string.brand_shield_notif_title))
            .setContentText(getString(R.string.brand_shield_notif_text, kittoku.osc.brand.Fa.digits(count.toString())))
            .setContentIntent(open)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        synchronized(statusLock) { statusClosed = true }
        jobStatusNotification?.cancel()
        startForeground(NOTIFICATION_DISCONNECT_ID, n)
    }

    private fun updateRequired(): Boolean = runCatching {
        kittoku.osc.brand.UpdateManager.required(kittoku.osc.brand.ConfigManager.current(this))
    }.getOrDefault(false)

    private fun isTunnelBusy() =
        controller != null || linuxTunnel != null || jobConnect?.isActive == true || jobReconnect?.isActive == true

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_VPN_SHIELD ||
            (intent?.action == VpnService.SERVICE_INTERFACE && BrandSession.shieldedApps(prefs).isNotEmpty() && !isTunnelBusy())
        ) {
            if (isTunnelBusy()) return START_STICKY          // the tunnel carries them already
            if (!startShield()) {
                // nothing to shield: a short foreground start was promised, then stop
                showShieldNotification(0)
                stopForeground(true)
                stopSelf()
                return START_NOT_STICKY
            }
            return START_STICKY
        }
        return when (intent?.action) {
            ACTION_VPN_CONNECT -> {
                controller?.kill(false, null)
                controller = null
                stopLinux()
                startShield(quiet = true)      // no gap for the shielded apps until the new tunnel

                kittoku.osc.brand.SessionTraffic.reset()
                cancelNotification(NOTIFICATION_ERROR_ID)
                cancelNotification(NOTIFICATION_RECONNECT_ID)
                beForegrounded()
                if (updateRequired()) {
                    // «آپدیت اجباری»: the owner stopped this version (always-on and boot starts too)
                    notifyError(getString(R.string.brand_update_required_text))
                    close()
                    return START_NOT_STICKY
                }
                resetReconnectionLife(prefs)
                if (getBooleanPrefValue(OscPrefKey.LOG_DO_SAVE_LOG, prefs)) {
                    prepareLogWriter()
                }
                if (logWriter == null) logWriter = kittoku.osc.control.LogWriter(null)   // memory only

                logWriter?.write("Establish VPN connection")

                startConnection()

                setRootState(true)

                START_STICKY
            }

            else -> {
                // ensure that reconnection has been completely canceled or done
                runBlocking { jobReconnect?.cancelAndJoin() }

                stopLinux()
                controller?.disconnect()
                controller = null

                // the user chose to disconnect: old error messages are not news
                cancelNotification(NOTIFICATION_ERROR_ID)
                cancelNotification(NOTIFICATION_RECONNECT_ID)
                BrandSession.clearError(prefs)

                close()

                START_NOT_STICKY
            }
        }
    }

    /**
     * Linux servers first (fastest working protocol, chosen automatically),
     * SSTP when none of them works.
     */
    private fun startConnection() {
        val linux = try {
            kittoku.osc.brand.ConfigManager.current(this).linuxServers.map { it.toString() }
        } catch (_: Exception) {
            emptyList()
        }
        if (linux.isEmpty()) {
            initializeClient()
            return
        }
        jobConnect?.cancel()
        jobConnect = scope.launch {
            val tunnel = LinuxTunnel(this@SstpVpnService, prefs, linux)
            linuxTunnel = tunnel
            val ok = try {
                tunnel.start()
            } catch (e: CancellationException) {
                throw e
            } catch (e: Throwable) {
                logWriter?.report("linux tunnel failed: $e")
                false
            }
            if (ok) return@launch
            tunnel.close()
            if (linuxTunnel === tunnel) linuxTunnel = null
            if (!isActive) return@launch
            logWriter?.report("no Linux protocol works, falling back to SSTP")
            initializeClient()
            watchLinuxReturn(linux)
        }
    }

    /**
     * On SSTP because no Linux protocol worked (a server down, «حالت تعمیر»,
     * a filter): every few minutes the Linux servers are probed again (this
     * app's own traffic is outside the tunnel) and the connection moves back
     * as soon as one works.
     */
    private fun watchLinuxReturn(linux: List<String>) {
        jobLinuxReturn?.cancel()
        jobLinuxReturn = scope.launch {
            while (isActive) {
                delay(LINUX_RETURN_EVERY_MS)
                if (controller == null || linuxTunnel != null) return@launch
                val probe = LinuxTunnel(this@SstpVpnService, prefs, linux)
                val works = try {
                    probe.anyWorks()
                } catch (e: CancellationException) {
                    throw e
                } catch (_: Throwable) {
                    false
                }
                // (a probe-only LinuxTunnel holds nothing; its close() would stop the engine)
                if (!works || controller == null || linuxTunnel != null) continue
                logWriter?.report("Linux servers work again, leaving SSTP")
                // the service stays: SSTP goes down, then the Linux tunnel starts
                // (closing the service here used to end the whole VPN)
                val old = controller
                controller = null
                if (old == null) return@launch
                old.kill(false, null) {
                    if (linuxTunnel == null && controller == null) {
                        startShield(quiet = true)
                        startConnection()
                    }
                }
                return@launch
            }
        }
    }

    private fun stopLinux() {
        jobLinuxReturn?.cancel()
        jobLinuxReturn = null
        jobConnect?.cancel()
        jobConnect = null
        linuxTunnel?.close()
        linuxTunnel = null
    }

    /** Every Linux protocol stopped working while connected. */
    internal fun onLinuxTunnelLost() {
        stopLinux()
        if (getIntPrefValue(OscPrefKey.RECONNECTION_LIFE, prefs) > 0) {
            launchJobReconnect()
        } else {
            notifyError("OSC: ERR_CONNECTION_LOST")
            close()
        }
    }

    private fun initializeClient() {
        kittoku.osc.brand.SessionTraffic.protocol = PROTOCOL_LABELS["sstp"] ?: "SSTP"
        controller = Controller(SharedBridge(this)).also {
            it.launchJobMain()
        }
    }

    private fun prepareLogWriter() {
        val currentDateTime = SimpleDateFormat("yyyyMMddHHmmss", Locale.getDefault()).format(Date())
        val filename = "log_osc_${currentDateTime}.txt"

        val prefURI = getURIPrefValue(OscPrefKey.LOG_DIR, prefs)
        if (prefURI == null) {
            notifyError("LOG: ERR_NULL_PREFERENCE")
            return
        }

        val dirURI = DocumentFile.fromTreeUri(this, prefURI)
        if (dirURI == null) {
            notifyError("LOG: ERR_NULL_DIRECTORY")
            return
        }

        val fileURI = dirURI.createFile("text/plain", filename)
        if (fileURI == null) {
            notifyError("LOG: ERR_NULL_FILE")
            return
        }

        val stream = contentResolver.openOutputStream(fileURI.uri, "wa")
        if (stream == null) {
            notifyError("LOG: ERR_NULL_STREAM")
            return
        }

        logWriter = LogWriter(stream)
    }

    internal fun launchJobReconnect() {
        startShield(quiet = true)              // the old tunnel is gone: no direct internet meanwhile
        jobReconnect = scope.launch {
            try {
                getIntPrefValue(OscPrefKey.RECONNECTION_LIFE, prefs).also {
                    val life = it - 1
                    setIntPrefValue(life, OscPrefKey.RECONNECTION_LIFE, prefs)

                    val message = "Reconnection will be tried (LIFE = $life)"
                    notifyMessage(getString(R.string.brand_reconnecting), NOTIFICATION_RECONNECT_ID, NOTIFICATION_RECONNECT_CHANNEL)
                    logWriter?.report(message)
                }

                delay(getIntPrefValue(OscPrefKey.RECONNECTION_INTERVAL, prefs) * 1000L)

                startConnection()
            } catch (_: CancellationException) { }
            finally {
                cancelNotification(NOTIFICATION_RECONNECT_ID)
            }
        }
    }

    private fun beForegroundedChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            arrayOf(
                NOTIFICATION_ERROR_CHANNEL,
                NOTIFICATION_RECONNECT_CHANNEL,
                NOTIFICATION_DISCONNECT_CHANNEL,
                NOTIFICATION_CERTIFICATE_CHANNEL,
            ).map {
                NotificationChannel(it, it, NotificationManager.IMPORTANCE_DEFAULT)
            }.also {
                notificationManager.createNotificationChannels(it)
            }
        }
    }

    private fun beForegrounded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            arrayOf(
                NOTIFICATION_ERROR_CHANNEL,
                NOTIFICATION_RECONNECT_CHANNEL,
                NOTIFICATION_DISCONNECT_CHANNEL,
                NOTIFICATION_CERTIFICATE_CHANNEL,
            ).map {
                NotificationChannel(it, it, NotificationManager.IMPORTANCE_DEFAULT)
            }.also {
                notificationManager.createNotificationChannels(it)
            }
        }

        val pendingIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, SstpVpnService::class.java).setAction(ACTION_VPN_DISCONNECT),
            PendingIntent.FLAG_ONE_SHOT or PendingIntent.FLAG_IMMUTABLE
        )

        synchronized(statusLock) { statusClosed = false }
        startForeground(NOTIFICATION_DISCONNECT_ID, statusNotification(pendingIntent))

        // keep duration and traffic in the notification up to date
        jobStatusNotification?.cancel()
        jobStatusNotification = scope.launch {
            while (true) {
                delay(2_000)
                val notification = statusNotification(pendingIntent)
                // never post after close(): a late post would leave a stale
                // "connected" notification that cannot be swiped away
                synchronized(statusLock) {
                    if (!statusClosed) tryNotify(notification, NOTIFICATION_DISCONNECT_ID)
                }
            }
        }
    }

    internal fun notifyMessage(message: String, id: Int, channel: String) {
        NotificationCompat.Builder(this, channel).also {
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.setContentText(message)
            it.priority = NotificationCompat.PRIORITY_DEFAULT
            it.setAutoCancel(true)

            tryNotify(it.build(), id)
        }
    }

    internal fun notifyError(message: String) {
        BrandSession.recordError(prefs, message)
        if (BrandSession.errorDetail(prefs)?.contains(message) != true) {
            BrandSession.recordErrorDetail(prefs, message, "")
        }
        notifyMessage(BrandSession.describeError(this, message), NOTIFICATION_ERROR_ID, NOTIFICATION_ERROR_CHANNEL)
    }

    private var jobStatusNotification: Job? = null
    private val statusLock = Any()
    @Volatile private var statusClosed = false

    private fun removeStatusNotification() {
        synchronized(statusLock) { statusClosed = true }
        jobStatusNotification?.cancel()
        jobStatusNotification = null
        cancelNotification(NOTIFICATION_DISCONNECT_ID)
    }

    /** Ongoing notification: state, connected time (system chronometer) and traffic. */
    private fun statusNotification(disconnect: PendingIntent): Notification {
        val traffic = kittoku.osc.brand.SessionTraffic
        val connected = getStringPrefValue(OscPrefKey.HOME_STATUS, prefs).isNotEmpty()
        if (connected && traffic.connectedSince == 0L) traffic.connectedSince = System.currentTimeMillis()

        val open = PendingIntent.getActivity(this, 1,
            Intent(this, kittoku.osc.brand.BrandActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)

        val fa = kittoku.osc.brand.Fa
        val usage = getString(R.string.brand_notif_usage,
            fa.size(traffic.downloaded.get()), fa.size(traffic.uploaded.get()))

        return NotificationCompat.Builder(this, NOTIFICATION_DISCONNECT_CHANNEL).also {
            it.priority = NotificationCompat.PRIORITY_LOW
            it.setOngoing(true)
            it.setOnlyAlertOnce(true)
            it.setSilent(true)
            it.setSmallIcon(R.drawable.ic_baseline_vpn_lock_24)
            it.setContentIntent(open)
            val title = getString(if (connected) R.string.brand_notif_connected else R.string.brand_state_connecting)
            // users are not told how they are connected (protocol, server)
            it.setContentTitle(title)
            if (connected) {
                it.setContentText(usage)
                it.setUsesChronometer(true)
                it.setShowWhen(true)
                it.setWhen(traffic.connectedSince)
            } else {
                it.setShowWhen(false)
            }
            it.addAction(R.drawable.ic_baseline_close_24, getString(R.string.brand_disconnect), disconnect)
        }.build()
    }

    internal fun tryNotify(notification: Notification, id: Int) {
        if (ActivityCompat.checkSelfPermission(
                this,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        ) {
            notificationManager.notify(id, notification)
        }
    }

    internal fun cancelNotification(id: Int) {
        notificationManager.cancel(id)
    }

    internal fun close() {
        // stop updating first, or a late update would bring the notification back
        removeStatusNotification()
        // «سپر VPN»: the shielded apps stay without internet while there is no tunnel
        if (startShield()) return
        stopForeground(true)
        cancelNotification(NOTIFICATION_DISCONNECT_ID)
        stopSelf()
    }

    override fun onDestroy() {
        logWriter?.write("Terminate VPN connection")
        logWriter?.close()
        logWriter = null

        removeStatusNotification()
        stopLinux()
        controller?.kill(false, null)
        controller = null
        closeShield()

        scope.cancel()

        setRootState(false)
        prefs.unregisterOnSharedPreferenceChangeListener(listener)
    }
}
