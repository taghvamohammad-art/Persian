package kittoku.osc.service

import android.content.SharedPreferences
import android.net.ConnectivityManager
import android.net.TrafficStats
import android.os.Process
import android.util.Log
import ir.persianvpn.pvcore.Pvcore
import kittoku.osc.brand.BrandSession
import kittoku.osc.brand.SessionTraffic
import kittoku.osc.control.UnderlyingNetworkWatcher
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.setStringPrefValue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject


private const val TAG = "LinuxTunnel"
private const val PROBE_TIMEOUT_MS = 7_000L
private const val CHECK_EVERY_MS = 25_000L
private const val CHECK_TIMEOUT_MS = 10_000L
private const val CHECK_FAILURES = 2          // in a row before switching
private const val XRAY_MTU = 1500
private const val AWG_MTU = 1280
private const val XRAY_ADDRESS = "172.19.0.1"

internal val PROTOCOL_LABELS = mapOf(
    "vless-reality-vision" to "Reality",
    "vless-xhttp-reality" to "XHTTP",
    "hysteria2" to "Hysteria2",
    "shadowsocks-2022" to "Shadowsocks",
    "amneziawg" to "AmneziaWG",
    "vless-xhttp-cdn" to "CDN",
    "vless-dns" to "DNS",
    "sstp" to "SSTP",
)

/**
 * The Linux servers (Xray protocols and AmneziaWG) through the pvcore
 * engine. Every protocol of every server is tried at once and the fastest
 * one that works is used; the user never chooses. While connected a
 * watchdog checks the tunnel and moves to the next best protocol when it
 * stops working (for example when one protocol gets filtered).
 *
 * The app's own package is outside the VPN, so the engine's connections to
 * the servers go out on the real network.
 */
internal class LinuxTunnel(
    private val service: SstpVpnService,
    private val prefs: SharedPreferences,
    private val servers: List<String>,
) {
    private data class Choice(val server: String, val name: String, val kind: String, val ms: Long,
                              val members: List<Choice> = emptyList())

    @Volatile private var closed = false
    private var watchdog: Job? = null
    private var trafficJob: Job? = null
    private var networkWatcher: UnderlyingNetworkWatcher? = null
    @Volatile internal var current: String = ""
        private set

    private val user get() = BrandSession.username(prefs)
    private val pass get() = BrandSession.password(prefs)

    /** Probes and connects. False when no Linux protocol works right now. */
    internal suspend fun start(exclude: String? = null): Boolean = withContext(Dispatchers.IO) {
        // the DNS tunnel tries the operator's own resolvers first
        runCatching {
            val cm = service.getSystemService(ConnectivityManager::class.java)
            val dns = cm.getLinkProperties(cm.activeNetwork)?.dnsServers.orEmpty()
            Pvcore.setResolvers(dns.mapNotNull { it.hostAddress }.filter { !it.contains(":") }.joinToString(","))
        }
        val choices = plan(probeAll()).filter { "${it.name}/${it.kind}" != exclude }
        for (c in choices) {
            if (closed || !isActive) return@withContext false
            if (connect(c)) return@withContext true
        }
        false
    }

    private suspend fun probeAll(): List<Choice> = coroutineScope {
        servers.map { server ->
            async(Dispatchers.IO) {
                val name = runCatching { JSONObject(server).optString("name", "") }.getOrDefault("")
                val result = try {
                    JSONObject(Pvcore.probe(server, user, pass, PROBE_TIMEOUT_MS))
                } catch (e: Exception) {
                    Log.w(TAG, "probe failed: $e")
                    return@async emptyList<Choice>()
                }
                service.logWriter?.report("probe $name: $result")
                result.keys().asSequence().filter { it != "errors" }.mapNotNull { kind ->
                    val ms = result.optLong(kind, -1)
                    if (ms >= 0) Choice(server, name, kind, ms) else null
                }.toList()
            }
        }.awaitAll().flatten().sortedBy { it.ms }
    }

    /**
     * The Xray protocols that work go together into one "pool": Xray keeps
     * measuring them and moves new connections to the fastest, so a slow or
     * blocked protocol is left without the tunnel going down. AmneziaWG has
     * its own tunnel and is used when it is clearly faster, or when nothing
     * else works; the DNS tunnel only as the last resort.
     */
    private fun plan(all: List<Choice>): List<Choice> {
        val members = all.filter { it.kind != "amneziawg" && it.kind != "vless-dns" }
        val pool = members.firstOrNull()?.let { Choice("", it.name, "pool", it.ms, members) }
        val awg = all.firstOrNull { it.kind == "amneziawg" }
        val out = mutableListOf<Choice>()
        if (pool != null && (awg == null || pool.ms <= awg.ms * 3 / 2)) {
            out += pool
            awg?.let { out += it }
        } else {
            awg?.let { out += it }
            pool?.let { out += it }
        }
        out += all.filter { it.kind == "vless-dns" }
        return out
    }

    private suspend fun connect(c: Choice): Boolean {
        val awg = c.kind == "amneziawg"
        val builder = service.Builder()
        try {
            builder.setSession(service.getString(kittoku.osc.R.string.app_name))
            if (awg) {
                builder.addAddress(Pvcore.awgAddress(user), 32)
                builder.setMtu(AWG_MTU)
            } else {
                builder.addAddress(XRAY_ADDRESS, 30)
                builder.setMtu(XRAY_MTU)
            }
            builder.addRoute("0.0.0.0", 0)
            builder.addDnsServer("1.1.1.1")
            builder.addDnsServer("8.8.8.8")
            // the engine's own sockets must not loop back into the tunnel
            builder.addDisallowedApplication(service.packageName)
            BrandSession.excludedApps(prefs).forEach {
                try { builder.addDisallowedApplication(it) } catch (_: Exception) { }
            }
        } catch (e: Exception) {
            Log.w(TAG, "builder: $e")
            return false
        }

        val pfd = try {
            builder.establish()
        } catch (e: Exception) {
            null
        } ?: return false
        // the engine owns the descriptor from here on and closes it
        val fd = pfd.detachFd().toLong()
        try {
            synchronized(this) {
                if (closed) {
                    android.os.ParcelFileDescriptor.adoptFd(fd.toInt()).close()
                    return false
                }
                when {
                    awg -> Pvcore.startAwg(c.server, user, pass, fd)
                    c.kind == "pool" -> {
                        val list = org.json.JSONArray()
                        c.members.forEach {
                            list.put(JSONObject().put("server", JSONObject(it.server)).put("kind", it.kind))
                        }
                        Pvcore.startXrayPool(list.toString(), user, pass, fd, XRAY_MTU.toLong())
                    }
                    else -> Pvcore.startXray(c.server, c.kind, user, pass, fd, XRAY_MTU.toLong())
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "start ${c.kind}: $e")
            service.logWriter?.report("start ${c.name}/${c.kind} failed: $e")
            return false        // pvcore has closed the descriptor
        }
        current = "${c.name}/${c.kind}"
        onConnected(c)
        return true
    }

    private suspend fun onConnected(c: Choice) {
        SessionTraffic.authFailures = 0
        val kind = c.members.firstOrNull()?.kind ?: c.kind
        SessionTraffic.protocol = PROTOCOL_LABELS[kind] ?: kind
        setStringPrefValue("connected", OscPrefKey.HOME_STATUS, prefs)   // only "connected or not"
        service.cancelNotification(NOTIFICATION_ERROR_ID)
        service.cancelNotification(NOTIFICATION_RECONNECT_ID)
        BrandSession.clearError(prefs)
        service.logWriter?.report("connected: ${c.name}/${c.kind} (${c.ms} ms)" +
            if (c.members.isEmpty()) "" else " " + c.members.joinToString(",") { "${it.name}/${it.kind}" })

        startTrafficCounter()
        startWatchdog()
        if (networkWatcher == null) {
            networkWatcher = UnderlyingNetworkWatcher(
                service.getSystemService(ConnectivityManager::class.java)
            ) { failover("network changed") }.also { it.start() }
        }
    }

    /** Engine traffic is this app's own traffic on the real network. */
    private fun startTrafficCounter() {
        trafficJob?.cancel()
        trafficJob = service.scope.launch {
            val uid = Process.myUid()
            var rx = TrafficStats.getUidRxBytes(uid)
            var tx = TrafficStats.getUidTxBytes(uid)
            if (rx < 0 || tx < 0) return@launch      // not supported on this phone
            while (isActive) {
                delay(2_000)
                val nrx = TrafficStats.getUidRxBytes(uid)
                val ntx = TrafficStats.getUidTxBytes(uid)
                if (nrx >= rx) SessionTraffic.downloaded.addAndGet(nrx - rx)
                if (ntx >= tx) SessionTraffic.uploaded.addAndGet(ntx - tx)
                rx = nrx
                tx = ntx
            }
        }
    }

    private fun startWatchdog() {
        watchdog?.cancel()
        watchdog = service.scope.launch {
            var failures = 0
            while (isActive && !closed) {
                delay(CHECK_EVERY_MS)
                val ms = withContext(Dispatchers.IO) { Pvcore.check(CHECK_TIMEOUT_MS) }
                failures = if (ms < 0) failures + 1 else 0
                if (failures >= CHECK_FAILURES) {
                    failover("check failed")
                    return@launch
                }
            }
        }
    }

    @Volatile private var switching = false

    /** The tunnel stopped working: next best protocol, or hand back to the service. */
    private fun failover(reason: String) {
        if (closed || switching) return
        switching = true
        service.scope.launch {
            try {
                service.logWriter?.report("linux tunnel: $reason, switching")
                val previous = current
                stopEngine()
                setStringPrefValue("", OscPrefKey.HOME_STATUS, prefs)
                if (closed) return@launch
                if (!start(exclude = previous) && !start()) {
                    if (!closed) service.onLinuxTunnelLost()
                }
            } finally {
                switching = false
            }
        }
    }

    private fun stopEngine() {
        watchdog?.cancel()
        watchdog = null
        trafficJob?.cancel()
        trafficJob = null
        synchronized(this) {
            runCatching { Pvcore.stop() }
        }
        current = ""
    }

    internal fun close() {
        closed = true
        networkWatcher?.close()
        networkWatcher = null
        val wasUp = current.isNotEmpty()
        stopEngine()
        if (wasUp) setStringPrefValue("", OscPrefKey.HOME_STATUS, prefs)
    }
}
