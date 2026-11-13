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
private const val CHECK_EVERY_MS = 15_000L
private const val CHECK_RETRY_MS = 3_000L     // a failed check is repeated this soon
private const val CHECK_TIMEOUT_MS = 8_000L
private const val CHECK_FAILURES = 2          // in a row before switching
private const val QUICK_CHECK_MS = 6_000L     // the remembered protocol must answer this fast
private const val OPTIMIZE_FIRST_MS = 4_000L
private const val OPTIMIZE_EVERY_MS = 15 * 60_000L
private const val LAST_CHOICE_KEY = "pv_last_choice"
private const val STALL_UP_BYTES = 16_384L
private const val STALL_DOWN_BYTES = 512L
private const val STALL_ROUNDS = 2
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
 * The protocol that worked last time is tried first, without probing, so
 * connecting is quick; then everything is probed in the background and the
 * tunnel moves to a clearly better choice without going down.
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
    private var optimizer: Job? = null
    @Volatile private var currentChoice: Choice? = null
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
        if (exclude == null) {
            remembered()?.let { last ->
                if (connect(last, quick = true)) {
                    startOptimizer(OPTIMIZE_FIRST_MS)
                    return@withContext true
                }
                service.logWriter?.report("remembered ${sig(last)} did not answer, probing all")
            }
        }
        val choices = plan(probeAll()).filter { "${it.name}/${it.kind}" != exclude }
        for (c in choices) {
            if (closed || !isActive) return@withContext false
            if (connect(c)) {
                startOptimizer(OPTIMIZE_EVERY_MS)
                return@withContext true
            }
        }
        false
    }

    private fun sig(c: Choice): String =
        if (c.kind == "pool") "pool:" + c.members.map { "${it.name}/${it.kind}" }.sorted().joinToString(",")
        else "${c.name}/${c.kind}"

    private fun serverByName(): Map<String, String> = servers.associateBy {
        runCatching { JSONObject(it).optString("name", "") }.getOrDefault("")
    }

    /** The choice that worked last time, with today's server details. */
    private fun remembered(): Choice? = runCatching {
        val o = JSONObject(prefs.getString(LAST_CHOICE_KEY, null) ?: return null)
        val byName = serverByName()
        fun one(j: JSONObject): Choice? {
            val name = j.getString("name")
            val server = byName[name] ?: return null
            val kind = j.getString("kind")
            val kinds = runCatching { JSONObject(server).getJSONArray("protocols") }.getOrNull()
            if (kinds != null && (0 until kinds.length()).none { kinds.optJSONObject(it)?.optString("type") == kind })
                return null                                   // that protocol is gone from the server
            return Choice(server, name, kind, 0)
        }
        if (o.getString("kind") == "pool") {
            val arr = o.getJSONArray("members")
            val members = (0 until arr.length()).mapNotNull { one(arr.getJSONObject(it)) }
            if (members.isEmpty()) null else Choice("", members[0].name, "pool", 0, members)
        } else one(o)
    }.getOrNull()

    private fun remember(c: Choice) {
        val o = JSONObject().put("name", c.name).put("kind", c.kind)
        if (c.kind == "pool") {
            val arr = org.json.JSONArray()
            c.members.forEach { arr.put(JSONObject().put("name", it.name).put("kind", it.kind)) }
            o.put("members", arr)
        }
        prefs.edit().putString(LAST_CHOICE_KEY, o.toString()).apply()
    }

    /**
     * While connected: probe everything now and then (the probes run outside
     * the tunnel) and move to a clearly faster choice. The engine replaces
     * its tunnel in place, so apps keep their connection.
     */
    private fun startOptimizer(firstDelay: Long) {
        optimizer?.cancel()
        optimizer = service.scope.launch {
            delay(firstDelay)
            while (isActive && !closed) {
                runCatching { optimizeOnce() }.onFailure { Log.w(TAG, "optimize: $it") }
                delay(OPTIMIZE_EVERY_MS)
            }
        }
    }

    private suspend fun optimizeOnce() {
        val cur = currentChoice ?: return
        if (closed || switching) return
        val all = probeAll()
        val best = plan(all).firstOrNull() ?: return
        if (closed || switching || currentChoice !== cur) return
        if (sig(best) == sig(cur)) {
            remember(best)
            return
        }
        val mine = if (cur.kind == "pool") cur.members else listOf(cur)
        val curMs = all.filter { a -> mine.any { it.name == a.name && it.kind == a.kind } }
            .minOfOrNull { it.ms } ?: -1L
        val better = curMs < 0 || (best.ms * 10 < curMs * 7 && curMs - best.ms > 40)
        service.logWriter?.report("optimize: now ${sig(cur)} ${curMs}ms, best ${sig(best)} ${best.ms}ms" +
            if (better) " -> switching" else "")
        if (!better) return
        switching = true
        val ok = try { connect(best) } finally { switching = false }
        if (!ok) failover("switch to ${sig(best)} failed")
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

    private suspend fun connect(c: Choice, quick: Boolean = false): Boolean {
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
        if (quick && !answers(c)) {
            synchronized(this) { runCatching { Pvcore.stop() } }
            return false
        }
        current = "${c.name}/${c.kind}"
        currentChoice = c
        onConnected(c)
        remember(c)
        return true
    }

    /** The remembered choice must really carry traffic before it counts as connected. */
    private suspend fun answers(c: Choice): Boolean = withContext(Dispatchers.IO) {
        if (c.kind != "amneziawg") return@withContext Pvcore.check(QUICK_CHECK_MS) >= 0
        val end = System.currentTimeMillis() + QUICK_CHECK_MS        // wait for the first handshake
        while (System.currentTimeMillis() < end) {
            if (Pvcore.check(0) >= 0) return@withContext true
            delay(300)
        }
        false
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

    /** (up, down) bytes between the apps and the Xray tunnel, or null. */
    private fun tunnelBytes(): Pair<Long, Long>? = runCatching {
        val (u, d) = Pvcore.tunnelBytes().trim().split(" ").map { it.toLong() }
        if (u < 0 || d < 0) null else u to d
    }.getOrNull()

    private fun startWatchdog() {
        watchdog?.cancel()
        watchdog = service.scope.launch {
            var failures = 0
            var stalls = 0
            var last = tunnelBytes()
            while (isActive && !closed) {
                delay(if (failures > 0) CHECK_RETRY_MS else CHECK_EVERY_MS)
                if (switching) continue
                // apps kept sending but got nothing back: stuck for them even if
                // the health check below passes
                val now = tunnelBytes()
                if (now != null && last != null) {
                    val up = now.first - last.first
                    val down = now.second - last.second
                    stalls = if (up > STALL_UP_BYTES && down < STALL_DOWN_BYTES) stalls + 1 else 0
                    if (stalls > 0) service.logWriter?.report("linux: apps sent $up B, got $down B ($current)")
                    if (stalls >= STALL_ROUNDS) {
                        failover("no data back for the apps")
                        return@launch
                    }
                }
                val ms = withContext(Dispatchers.IO) { Pvcore.check(CHECK_TIMEOUT_MS) }
                last = tunnelBytes() ?: now           // the check's own bytes do not count
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
        optimizer?.cancel()
        optimizer = null
        currentChoice = null
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
