package kittoku.osc.brand

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.content.SharedPreferences
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import com.google.android.material.button.MaterialButton
import ir.persianvpn.pvcore.Pvcore
import kittoku.osc.BuildConfig
import kittoku.osc.R
import kittoku.osc.control.DiagLog
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getStringPrefValue
import kittoku.osc.service.PROTOCOL_LABELS
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Socket
import java.net.URL


/**
 * «تست و عیب‌یابی»: for the owner when "connected but nothing loads".
 * Opened by a long press on the connect button's status text (hidden from
 * ordinary users, harmless if found). It checks, each step on its own:
 * the phone's own internet, the tunnel from inside (the engine fetches
 * pages, resolves a name and asks DNS over UDP exactly as apps do), whether
 * apps' traffic goes in and comes back, every protocol of every server, and
 * the SSTP server; then shows the recent connection log. The report can be
 * copied or shared to send to support.
 */
class DiagnosticsActivity : AppCompatActivity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main)
    private var job: Job? = null
    private lateinit var prefs: SharedPreferences
    private lateinit var out: TextView
    private lateinit var scroll: ScrollView
    private lateinit var runButton: MaterialButton
    private val report = StringBuilder()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        val dp = resources.displayMetrics.density
        val pad = (16 * dp).toInt()

        val title = TextView(this).apply {
            text = getString(R.string.brand_diag_title)
            textSize = 20f
            setTextColor(ContextCompat.getColor(context, R.color.brand_text))
            setPadding(0, 0, 0, pad / 2)
        }
        val hint = TextView(this).apply {
            text = getString(R.string.brand_diag_hint)
            textSize = 13f
            setTextColor(ContextCompat.getColor(context, R.color.brand_text_dim))
            setPadding(0, 0, 0, pad / 2)
        }
        runButton = MaterialButton(this).apply {
            text = getString(R.string.brand_diag_run)
            setOnClickListener { runAll() }
        }
        val copy = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.brand_diag_copy)
            setOnClickListener { copyReport() }
        }
        val share = MaterialButton(this, null, com.google.android.material.R.attr.materialButtonOutlinedStyle).apply {
            text = getString(R.string.brand_diag_share)
            setOnClickListener { shareReport() }
        }
        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            val lp = { LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f).apply {
                marginStart = pad / 4; marginEnd = pad / 4 } }
            addView(runButton, lp())
            addView(copy, lp())
            addView(share, lp())
        }
        out = TextView(this).apply {
            typeface = Typeface.MONOSPACE
            textSize = 12f
            setTextIsSelectable(true)
            textDirection = View.TEXT_DIRECTION_LTR
            setTextColor(ContextCompat.getColor(context, R.color.brand_text))
            setPadding(0, pad / 2, 0, pad)
        }
        scroll = ScrollView(this).apply { addView(out) }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad * 2, pad, pad)
            addView(title)
            addView(hint)
            addView(buttons)
            addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        }
        setContentView(root)
        Tv.centre(root)
        runAll()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun line(s: String = "") {
        report.append(s).append('\n')
        out.text = report.toString()
        scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
    }

    private fun runAll() {
        if (job?.isActive == true) return
        report.clear()
        runButton.isEnabled = false
        job = scope.launch {
            try {
                runTests()
            } catch (e: Exception) {
                line("✗ ${e.javaClass.simpleName}: ${e.message}")
            } finally {
                runButton.isEnabled = true
                line()
                line("— پایان —")
            }
        }
    }

    private suspend fun runTests() {
        val user = BrandSession.username(prefs)
        line("Persian VPN ${BuildConfig.VERSION_NAME} (${BuildConfig.VERSION_CODE}) · Android ${Build.VERSION.RELEASE} · ${Build.MANUFACTURER} ${Build.MODEL}")
        line("user: $user · ${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US).format(java.util.Date())}")
        line(networks())
        val connected = getStringPrefValue(OscPrefKey.HOME_STATUS, prefs).isNotEmpty()
        val engine = runCatching { Pvcore.running() }.getOrDefault("")
        line("VPN: ${if (connected) "وصل" else "وصل نیست"} · protocol: ${SessionTraffic.protocol.ifEmpty { "-" }}" +
            " · engine: ${engine.ifEmpty { "-" }}")
        line("traffic: ↓ ${bytes(SessionTraffic.downloaded.get())}  ↑ ${bytes(SessionTraffic.uploaded.get())}")
        val excluded = BrandSession.excludedApps(prefs).size
        val shielded = BrandSession.shieldedApps(prefs).size
        if (excluded + shielded > 0) line("apps outside VPN: $excluded · shield: $shielded")

        line()
        line("① اینترنت خود گوشی (بدون VPN)")
        line(withContext(Dispatchers.IO) { direct("https://www.gstatic.com/generate_204") })
        line(withContext(Dispatchers.IO) { direct("https://1.1.1.1/cdn-cgi/trace") })

        line()
        line("② داخل تانل (همان راهی که برنامه‌ها می‌روند)")
        if (engine.isEmpty()) {
            line(if (connected) "  SSTP (میکروتیک): این تست برای SSTP نیست؛ بخش ⑤ و گزارش را ببینید"
                 else "  VPN وصل نیست؛ اول وصل شوید و دوباره تست بزنید")
        } else {
            val d = withContext(Dispatchers.IO) { JSONObject(Pvcore.diagnose(15_000L)) }
            describeEngine(d)
            line()
            line("③ آیا ترافیک برنامه‌ها می‌رود و برمی‌گردد؟ (۸ ثانیه؛ در این مدت یک سایت باز کنید)")
            val a = tunnelBytes()
            delay(8_000)
            val b = tunnelBytes()
            if (a == null || b == null) {
                line("  (برای AmneziaWG شمارنده‌ی جدا نیست؛ ↓↑ بخش ② را ببینید)")
            } else {
                val up = b.first - a.first
                val down = b.second - a.second
                line("  برنامه‌ها فرستادند ${bytes(up)} · گرفتند ${bytes(down)}")
                line(when {
                    up == 0L -> "  ⚠ چیزی وارد تانل نشد (اگر سایتی باز کردید: برنامه خارج از VPN است؟)"
                    down == 0L -> "  ✗ رفت ولی برنگشت: تانل برای برنامه‌ها گیر کرده"
                    else -> "  ✓ رفت‌وبرگشت دارد"
                })
            }
        }

        line()
        line("④ همه‌ی پروتکل‌ها (هر کدام جدا، بیرون از تانل)")
        val servers = runCatching { ConfigManager.current(this).linuxServers.map { it.toString() } }.getOrDefault(emptyList())
        if (servers.isEmpty()) line("  سرور لینوکسی در تنظیمات نیست")
        for (s in servers) {
            val name = runCatching { JSONObject(s).optString("name") }.getOrDefault("?")
            line("  $name:")
            val r = withContext(Dispatchers.IO) {
                runCatching { JSONObject(Pvcore.probe(s, user, BrandSession.password(prefs), 8_000L)) }
            }
            r.onFailure { line("    ✗ ${it.message}") }.onSuccess { j ->
                val errors = j.optJSONObject("errors")
                val kinds = (j.keys().asSequence().filter { it != "errors" } +
                    (errors?.keys()?.asSequence() ?: emptySequence())).toSortedSet()
                for (k in kinds) {
                    val ms = j.optLong(k, -1)
                    val label = PROTOCOL_LABELS[k] ?: k
                    line(if (ms >= 0) "    ✓ $label ${ms}ms" else "    ✗ $label ${errors?.optString(k).orEmpty().take(90)}")
                }
            }
        }

        line()
        line("⑤ سرور SSTP (میکروتیک)")
        val host = getStringPrefValue(OscPrefKey.HOME_HOSTNAME, prefs)
        if (host.isEmpty()) line("  -") else line(withContext(Dispatchers.IO) { tcp(host, 443) })

        line()
        line("⑥ گزارش اتصال (آخرین خط‌ها)")
        DiagLog.all().takeLast(60).forEach { line("  $it") }
    }

    private fun describeEngine(d: JSONObject) {
        line("  engine: ${d.optString("running")}")
        d.optString("error").takeIf { it.isNotEmpty() }?.let { line("  ✗ $it") }
        d.optJSONObject("awg")?.let { a ->
            val age = a.optInt("handshake_age_s", -1)
            line(if (age in 0..200) "  ✓ AmneziaWG handshake ${age}s پیش" else "  ✗ AmneziaWG handshake نشده یا قدیمی ($age)")
            line("  ↓ ${bytes(a.optLong("rx_bytes"))}  ↑ ${bytes(a.optLong("tx_bytes"))}")
            if (a.optLong("tx_bytes") > 0 && a.optLong("rx_bytes") < 1024)
                line("  ⚠ می‌فرستد ولی تقریباً چیزی نمی‌گیرد: راه UDP به سرور بسته است؟")
        }
        val names = mapOf("trace" to "صفحه با IP (بدون DNS)", "name" to "صفحه با اسم (DNS سمت سرور)",
            "dns_udp" to "DNS روی UDP (مثل برنامه‌ها)", "download" to "دانلود ۲ مگابایت")
        val steps = d.optJSONArray("steps") ?: return
        for (i in 0 until steps.length()) {
            val s = steps.getJSONObject(i)
            val label = names[s.optString("name")] ?: s.optString("name")
            val detail = if (s.optBoolean("ok")) s.optString("info") else s.optString("error").take(120)
            line("  ${if (s.optBoolean("ok")) "✓" else "✗"} $label ${s.optInt("ms")}ms $detail")
        }
        val failed = (0 until steps.length()).map { steps.getJSONObject(it) }.filter { !it.optBoolean("ok") }
            .map { it.optString("name") }.toSet()
        when {
            failed.isEmpty() -> line("  → تانل سالم است؛ اگر برنامه‌ای کار نمی‌کند، بخش ③ را ببینید")
            "trace" in failed && "name" in failed -> line("  → خود پروتکل کار نمی‌کند (سرور یا فیلتر)")
            failed == setOf("dns_udp") -> line("  → فقط DNS روی UDP خراب است: سایت‌ها باز نمی‌شوند ولی تلگرام شاید")
            "download" in failed && failed.size == 1 -> line("  → وصل است ولی دانلود کامل نشد (کند یا قطع‌ووصل)")
        }
    }

    private fun bytes(n: Long): String = when {
        n >= 1 shl 20 -> String.format(java.util.Locale.US, "%.1f MB", n / 1048576.0)
        n >= 1024 -> String.format(java.util.Locale.US, "%.1f KB", n / 1024.0)
        else -> "$n B"
    }

    private fun tunnelBytes(): Pair<Long, Long>? {
        val p = runCatching { Pvcore.tunnelBytes() }.getOrDefault("-1 -1").trim().split(" ")
        val up = p.getOrNull(0)?.toLongOrNull() ?: -1
        val down = p.getOrNull(1)?.toLongOrNull() ?: -1
        return if (up < 0 || down < 0) null else up to down
    }

    private fun networks(): String {
        val cm = getSystemService(ConnectivityManager::class.java)
        val parts = mutableListOf<String>()
        for (n in cm.allNetworks) {
            val c = cm.getNetworkCapabilities(n) ?: continue
            val kind = when {
                c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN"
                c.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
                c.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "موبایل"
                else -> "other"
            }
            val ok = c.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            val dns = cm.getLinkProperties(n)?.dnsServers.orEmpty().joinToString(",") { it.hostAddress ?: "" }
            parts += "$kind${if (ok) "✓" else ""}${if (dns.isNotEmpty()) " dns=$dns" else ""}"
        }
        return "networks: " + parts.joinToString(" · ").ifEmpty { "-" }
    }

    /** On the phone's own network (this app is outside its VPN). */
    private fun direct(url: String): String {
        val start = System.currentTimeMillis()
        return try {
            val c = underlying()?.openConnection(URL(url)) ?: URL(url).openConnection()
            (c as HttpURLConnection).run {
                connectTimeout = 8_000
                readTimeout = 8_000
                val code = responseCode
                val body = runCatching { inputStream.bufferedReader().readText() }.getOrDefault("")
                disconnect()
                val ms = System.currentTimeMillis() - start
                val info = body.lines().filter { it.startsWith("ip=") || it.startsWith("loc=") }.joinToString(" ")
                "  ✓ ${URL(url).host} HTTP $code ${ms}ms $info"
            }
        } catch (e: Exception) {
            "  ✗ ${URL(url).host}: ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}"
        }
    }

    private fun underlying(): Network? {
        val cm = getSystemService(ConnectivityManager::class.java)
        return cm.allNetworks.firstOrNull {
            val c = cm.getNetworkCapabilities(it)
            c != null && !c.hasTransport(NetworkCapabilities.TRANSPORT_VPN) &&
                c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }

    private fun tcp(host: String, port: Int): String {
        val start = System.currentTimeMillis()
        return try {
            val s = underlying()?.socketFactory?.createSocket() ?: Socket()
            s.use { it.connect(InetSocketAddress(host, port), 8_000) }
            "  ✓ $host:$port باز است ${System.currentTimeMillis() - start}ms"
        } catch (e: Exception) {
            "  ✗ $host:$port ${e.javaClass.simpleName} ${e.message.orEmpty().take(80)}"
        }
    }

    private fun copyReport() {
        val cm = getSystemService(ClipboardManager::class.java)
        cm.setPrimaryClip(ClipData.newPlainText("Persian VPN test", report.toString()))
        Toast.makeText(this, R.string.brand_diag_copied, Toast.LENGTH_SHORT).show()
    }

    private fun shareReport() {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_TEXT, report.toString())
        }
        runCatching { startActivity(Intent.createChooser(send, getString(R.string.brand_diag_share))) }
    }
}
