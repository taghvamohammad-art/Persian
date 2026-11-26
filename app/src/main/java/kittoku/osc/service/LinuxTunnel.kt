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
private const val FAILURE_WINDOW_MS = 60 * 60_000L  // breakdowns older than this are forgotten
// Speed: a filter can let the server's address answer small requests fast
// while carrying only a few KB/s; then CDN (Cloudflare, not that address) goes first.
private const val SPEED_SECONDS = 3L
private const val SPEED_GOOD_KBPS = 150L      // fast enough: nothing to compare
private const val SPEED_SLOW_KBPS = 40L       // below this the path counts as throttled
private const val SPEED_CHECK_EVERY_MS = 15 * 60_000L  // while connected and in use
private const val SPEED_RECHECK_MS = 60_000L  // a slow result is confirmed once before switching
private const val CDN = "vless-xhttp-cdn"
private const val LAST_GOOD_KEY = "pv_last_good_server"
/** Tried first: they look like ordinary HTTPS (Reality) or have their own disguise. */
private val STEALTH_KINDS = setOf("vless-reality-vision", "vless-xhttp-reality", "amneziawg")
/** Carry traffic only when nothing disguised works. */
private val WEAK_KINDS = setOf("shadowsocks-2022", "hysteria2")
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
    @Volatile private var currentChoice: Choice? = null

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
        // after a breakdown every protocol is tried, so the fallbacks are there too
        val probes = probeAll(full = exclude != null)
        val choices = bySpeed(plan(probes), probes).filter { "${it.name}/${it.kind}" != exclude }
        for (c in choices) {
            if (closed || !isActive) return@withContext false
            if (connect(c)) return@withContext true
        }
        false
    }

    /** Whether any Linux protocol (not the DNS tunnel) works now; nothing is started. */
    internal suspend fun anyWorks(): Boolean = withContext(Dispatchers.IO) {
        probeAll().any { it.kind != "vless-dns" }
    }

    /**
     * First only the disguised protocols (Reality looks like ordinary HTTPS,
     * AmneziaWG has its own disguise), one server at a time, the one that
     * worked last first, stopping at the first server where one works: trying
     * every protocol of every server from one phone within seconds, on every
     * connect, is itself a pattern a filter can see. Only when none of them
     * works, every protocol of every server together.
     */
    private suspend fun probeAll(full: Boolean = false): List<Choice> {
        val last = prefs.getString(LAST_GOOD_KEY, "").orEmpty()
        val ordered = servers.sortedBy { if (nameOf(it) == last) 0 else 1 }
        if (!full) for (server in ordered) {
            val part = onlyKinds(server, STEALTH_KINDS) ?: continue
            val res = probeOne(server, part)
            if (res.isNotEmpty()) return res.sortedBy { it.ms }
        }
        return coroutineScope {
            servers.map { server -> async(Dispatchers.IO) { probeOne(server, server) } }.awaitAll()
        }.flatten().sortedBy { it.ms }
    }

    private fun nameOf(server: String) =
        runCatching { JSONObject(server).optString("name", "") }.getOrDefault("")

    /** The server entry with only the given protocols; null when it has none of them. */
    private fun onlyKinds(server: String, kinds: Set<String>): String? = runCatching {
        val o = JSONObject(server)
        val list = o.optJSONArray("protocols") ?: return@runCatching null
        val keep = org.json.JSONArray()
        for (i in 0 until list.length()) {
            val pr = list.optJSONObject(i) ?: continue
            if (pr.optString("type") in kinds) keep.put(pr)
        }
        if (keep.length() == 0) null else o.put("protocols", keep).toString()
    }.getOrNull()

    /** Probes [probe] (all or some protocols of [server]); choices keep the full entry. */
    private suspend fun probeOne(server: String, probe: String): List<Choice> {
        val name = nameOf(server)
        val result = try {
            JSONObject(Pvcore.probe(probe, user, pass, PROBE_TIMEOUT_MS))
        } catch (e: Exception) {
            Log.w(TAG, "probe failed: $e")
            return emptyList()
        }
        service.logWriter?.report("probe $name: $result")
        return result.keys().asSequence().filter { it != "errors" }.mapNotNull { kind ->
            val ms = result.optLong(kind, -1)
            if (ms >= 0) Choice(server, name, kind, ms) else null
        }.toList()
    }

    /**
     * The Xray protocols that work go together into one "pool": Xray keeps
     * measuring them and moves new connections to the fastest, so a slow or
     * blocked protocol is left without the tunnel going down. The pool and
     * AmneziaWG (its own tunnel) are put in order by speed, where each time
     * one of them broke down in the last hour on this phone counts as one
     * more of its measured time: the fast and steady one first. The DNS
     * tunnel only as the last resort.
     */
    private suspend fun plan(all: List<Choice>): List<Choice> {
        val xray = all.filter { it.kind != "amneziawg" && it.kind != "vless-dns" && it.kind !in WEAK_KINDS }
        // one server at a time: traffic spread over two servers would open two
        // User Manager sessions, and a one-user account is refused on the second
        val members = xray.firstOrNull()?.let { best -> xray.filter { it.name == best.name } }.orEmpty()
        val pool = members.firstOrNull()?.let { Choice("", it.name, "pool", it.ms, members) }
        // Shadowsocks (plain random bytes) and Hysteria2 (QUIC-like) are what
        // filters pick out by statistics, and then the whole address is slowed:
        // they carry traffic only when nothing disguised works
        val weakAll = all.filter { it.kind in WEAK_KINDS }
        val weakMembers = weakAll.firstOrNull()?.let { b -> weakAll.filter { it.name == b.name } }.orEmpty()
        val weak = weakMembers.firstOrNull()?.let { Choice("", it.name, "pool", it.ms, weakMembers) }
        // hotspot sharing needs the Xray tunnel (its proxy goes through it)
        val choice = BrandSession.protocolChoice(service, prefs)
        val awg = all.firstOrNull { it.kind == "amneziawg" && !BrandSession.shareEnabled(prefs) }
            .takeIf { choice != "xray" }
        val out = when {
            // the user's choice goes first; the other stays as a fallback so
            // a blocked choice does not leave the phone without internet
            choice == "awg" && awg != null -> listOfNotNull(awg, pool).toMutableList()
            else -> listOfNotNull(pool, awg).sortedBy { score(it) }.toMutableList()
        }
        if (out.size == 2) {
            service.logWriter?.report("plan: " + out.joinToString(" < ") {
                "${it.kind} ${it.ms}ms×${1 + recentFailures(group(it))}"
            })
        }
        if (weak != null) out += weak
        out += all.filter { it.kind == "vless-dns" }
        return out
    }

    /**
     * The first choice's real speed (a download of at most 1 MB): when it is
     * throttled and CDN of the same server carries clearly more, CDN alone
     * goes first (in a pool Xray's balancer measures latency only and would
     * keep the throttled address). The rest stay as fallbacks.
     */
    private suspend fun bySpeed(choices: List<Choice>, probes: List<Choice>): List<Choice> = withContext(Dispatchers.IO) {
        val first = choices.firstOrNull() ?: return@withContext choices
        if (first.kind == CDN || first.kind == "vless-dns") return@withContext choices
        val sample = if (first.kind == "pool") first.members.firstOrNull { it.kind != CDN } else first
        sample ?: return@withContext choices
        val probed = probes.firstOrNull { it.kind == CDN && it.server == sample.server }
            ?: probes.firstOrNull { it.kind == CDN }
        val hasCdn = probed != null || servers.any { onlyKinds(it, setOf(CDN)) != null }
        if (!hasCdn) return@withContext choices
        val direct = runCatching { Pvcore.speed(sample.server, sample.kind, user, pass, SPEED_SECONDS) }.getOrDefault(-1L)
        if (direct >= SPEED_GOOD_KBPS) {
            service.logWriter?.report("speed ${sample.name}/${sample.kind}: $direct KB/s")
            return@withContext choices
        }
        // the first probe tries only the disguised protocols: CDN is probed
        // now, when the direct address turns out slow
        var found = probed
        if (found == null) {
            for (sv in listOf(sample.server) + servers.filter { it != sample.server }) {
                val part = onlyKinds(sv, setOf(CDN)) ?: continue
                found = probeOne(sv, part).firstOrNull()
                if (found != null) break
            }
        }
        val cdn = found ?: return@withContext choices
        val viaCdn = runCatching { Pvcore.speed(cdn.server, CDN, user, pass, SPEED_SECONDS) }.getOrDefault(-1L)
        service.logWriter?.report("speed ${sample.name}/${sample.kind}: $direct KB/s, ${cdn.name}/cdn: $viaCdn KB/s")
        if (viaCdn >= SPEED_SLOW_KBPS && viaCdn >= 2 * maxOf(direct, 1L)) {
            service.logWriter?.report("plan: cdn first (the server's address is slow)")
            listOf(cdn) + choices
        } else choices
    }

    private fun group(c: Choice) = if (c.kind == "amneziawg") "amneziawg" else "pool"

    private fun score(c: Choice): Long = c.ms * (1 + recentFailures(group(c)))

    private fun failureKey(group: String) = "pv_failures_$group"

    private fun recentFailures(group: String): Int = failureTimes(group).size

    private fun failureTimes(group: String): List<Long> {
        val now = System.currentTimeMillis()
        return prefs.getString(failureKey(group), "").orEmpty().split(",")
            .mapNotNull { it.toLongOrNull() }.filter { now - it < FAILURE_WINDOW_MS }
    }

    private fun noteFailure(c: Choice?) {
        c ?: return
        val g = group(c)
        val times = failureTimes(g) + System.currentTimeMillis()
        prefs.edit().putString(failureKey(g), times.takeLast(20).joinToString(",")).apply()
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
            if (BrandSession.shieldedApps(prefs).isNotEmpty()) {
                // «سپر VPN»: the tunnel is IPv4 only; IPv6 would otherwise go around it
                builder.addAddress("fd00:7076:74::1", 128)
                builder.addRoute("::", 0)
            }
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
        service.onTunnelUp()
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
        currentChoice = c
        prefs.edit().putString(LAST_GOOD_KEY, c.name).apply()
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
        startShare()
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
            var lastSpeed = System.currentTimeMillis()
            var lastDown = SessionTraffic.downloaded.get()
            var slowOnce = false
            while (isActive && !closed) {
                delay(CHECK_EVERY_MS)
                // a hotspot turned on (or off) after connecting
                if (BrandSession.shareEnabled(prefs)) BrandSession.updateShareNets(service)
                val ms = withContext(Dispatchers.IO) { Pvcore.check(CHECK_TIMEOUT_MS) }
                failures = if (ms < 0) failures + 1 else 0
                if (ms < 0) {
                    service.logWriter?.report("check $current failed ($failures)")
                    // every failed check counts against that kind, kept across
                    // reconnects: a tunnel that stalls and is reconnected by hand
                    // must not be picked again just for being fast
                    noteFailure(currentChoice)
                }
                if (failures >= CHECK_FAILURES) {
                    failover("check failed")
                    return@launch
                }
                // a tunnel that works but crawls (the server's address throttled)
                val now = System.currentTimeMillis()
                val every = if (slowOnce) SPEED_RECHECK_MS else SPEED_CHECK_EVERY_MS
                if (ms >= 0 && now - lastSpeed >= every) {
                    lastSpeed = now
                    val down = SessionTraffic.downloaded.get()
                    // more than the checks' own downloads: someone is using the tunnel
                    val used = down - lastDown > 2_000_000L
                    lastDown = down
                    if (used || slowOnce) {
                        val kbps = withContext(Dispatchers.IO) { Pvcore.speedRunning(SPEED_SECONDS) }
                        if (kbps >= -1L) service.logWriter?.report("speed $current: $kbps KB/s")
                        when {
                            kbps < 0L -> slowOnce = false          // not measurable / the check above covers failures
                            kbps >= SPEED_SLOW_KBPS -> slowOnce = false
                            slowOnce -> {
                                failover("slow")
                                return@launch
                            }
                            else -> slowOnce = true
                        }
                    }
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
                if (reason == "check failed" || reason == "slow") {
                    // Probe first while the tunnel keeps carrying traffic: a short
                    // hiccup on a lossy network used to tear the tunnel down and
                    // build the very same one again, cutting every connection
                    // for ten seconds. Only a better choice is worth that.
                    val probes = probeAll()
                    val best = bySpeed(plan(probes), probes).firstOrNull()
                    if (closed) return@launch
                    val now = currentChoice
                    if (best != null && now != null && sameChoice(best, now)) {
                        service.logWriter?.report("linux tunnel: still the best ($previous), kept")
                        startWatchdog()
                        return@launch
                    }
                }
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

    private fun sameChoice(a: Choice, b: Choice): Boolean {
        if (a.kind != b.kind) return false
        if (a.kind != "pool") return a.name == b.name
        // a pool on the same server is kept even if a probe in the middle of a
        // hiccup missed one of its protocols: Xray's balancer inside the pool
        // already leaves a failing protocol out and takes it back when it returns
        // (the weak pool is not the same as the disguised one)
        val weakA = a.members.any { it.kind in WEAK_KINDS }
        val weakB = b.members.any { it.kind in WEAK_KINDS }
        return weakA == weakB && a.members.map { it.name }.toSet() == b.members.map { it.name }.toSet()
    }

    /** The hotspot proxy, when the user turned sharing on (BrandSession.shareEnabled). */
    internal suspend fun startShare() {
        if (!BrandSession.shareEnabled(prefs)) return
        val cm = service.getSystemService(android.net.ConnectivityManager::class.java)
        val uplink = runCatching { cm.getLinkProperties(cm.activeNetwork)?.interfaceName }.getOrNull() ?: ""
        BrandSession.updateShareNets(service)
        runCatching { Pvcore.startShare(BrandSession.SHARE_PORT.toLong(), uplink) }
            .onFailure { service.logWriter?.report("share: ${it.message}") }
    }

    private fun stopEngine() {
        runCatching { Pvcore.stopShare() }
        watchdog?.cancel()
        watchdog = null
        trafficJob?.cancel()
        trafficJob = null
        synchronized(this) {
            runCatching { Pvcore.stop() }
        }
        current = ""
        currentChoice = null
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
