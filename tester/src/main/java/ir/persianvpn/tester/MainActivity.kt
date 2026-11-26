package ir.persianvpn.tester

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Intent
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.telephony.TelephonyManager
import android.text.InputType
import android.util.Base64
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import ir.persianvpn.pvcore.Pvcore
import org.json.JSONArray
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * «تست سرورها»: every protocol, and every way of each, of the published
 * Linux servers (and the lab protocols, when the release tool's export was
 * added): first whether each connects (three requests), then the speed of
 * the ones that did (an 8 s download), then a ranking. No VPN: the engine
 * connects by itself.
 */
class MainActivity : AppCompatActivity() {
    // the app's colours
    private val bg1 = Color.parseColor("#0B2F45")
    private val bg2 = Color.parseColor("#0E4C5A")
    private val card = Color.parseColor("#1A4A5E")
    private val accent = Color.parseColor("#2EE6C5")
    private val ink = Color.parseColor("#E8F4F2")
    private val muted = Color.parseColor("#9DB8C0")
    private val bad = Color.parseColor("#FF7A7A")
    private val warn = Color.parseColor("#F5C451")

    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var status: TextView
    private lateinit var list: LinearLayout
    private lateinit var scroll: ScrollView
    private lateinit var start: Button
    @Volatile private var running = false
    @Volatile private var stop = false
    private val report = StringBuilder()
    private val prefs by lazy { getSharedPreferences("tester", MODE_PRIVATE) }
    private val dp by lazy { resources.displayMetrics.density }
    private fun px(v: Int) = (v * dp).toInt()

    private var published = JSONArray()           // linux_servers of the app config

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.statusBarColor = bg1
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutDirection = View.LAYOUT_DIRECTION_RTL
            background = GradientDrawable(GradientDrawable.Orientation.TOP_BOTTOM, intArrayOf(bg1, bg2))
        }
        // keep clear of the status and navigation bars (edge to edge on new Android)
        ViewCompat.setOnApplyWindowInsetsListener(root) { v, insets ->
            val b = insets.getInsets(WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.ime())
            v.setPadding(px(16), b.top + px(12), px(16), b.bottom + px(12))
            insets
        }

        root.addView(text("تست سرورها", 24f, ink, bold = true))
        status = text("", 13f, muted).apply { setPadding(0, px(4), 0, px(12)) }
        root.addView(status)

        val login = box()
        user = field("نام کاربری", prefs.getString("user", ""), password = false)
        pass = field("رمز", prefs.getString("pass", ""), password = true)
        login.addView(user)
        login.addView(pass, LinearLayout.LayoutParams(-1, -2).apply { topMargin = px(8) })
        root.addView(login)

        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, px(12), 0, px(8)) }
        start = pill("شروع تست", primary = true) { if (running) stop = true else run() }
        row.addView(start, LinearLayout.LayoutParams(0, px(52), 2f))
        row.addView(pill("🧪 پروتکل‌های آزمایشی", primary = false) { importText(clipText()) },
            LinearLayout.LayoutParams(0, px(52), 1.4f).apply { marginStart = px(8) })
        root.addView(row)

        list = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        scroll = ScrollView(this).apply { addView(list) }
        root.addView(scroll, LinearLayout.LayoutParams(-1, 0, 1f))

        val bottom = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL; setPadding(0, px(8), 0, 0) }
        bottom.addView(pill("کپی گزارش", primary = false) { copyReport() }, LinearLayout.LayoutParams(0, px(46), 1f))
        bottom.addView(pill("ارسال گزارش", primary = false) { shareReport() },
            LinearLayout.LayoutParams(0, px(46), 1f).apply { marginStart = px(8) })
        root.addView(bottom)
        setContentView(root)

        hint("نام کاربری و رمز یک حساب فعال را بزنید و «شروع تست». VPN را قبلش قطع کنید.\n" +
            "برای پروتکل‌های آزمایشی: در ابزار انتشار «🧪 پروتکل‌های آزمایشی + خروجی برای اپ تست» را بزنید، " +
            "متن را کپی کنید و اینجا «🧪 پروتکل‌های آزمایشی» را بزنید (یا از تلگرام به این اپ «اشتراک» بدهید).")
        intent?.let { handleShare(it) }
        loadPublished()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleShare(intent)
    }

    // ---------------------------------------------------------------- views

    private fun text(s: String, size: Float, color: Int, bold: Boolean = false) = TextView(this).apply {
        text = s; textSize = size; setTextColor(color)
        if (bold) typeface = Typeface.DEFAULT_BOLD
    }

    private fun rounded(color: Int, r: Int = 16, stroke: Int? = null) = GradientDrawable().apply {
        setColor(color); cornerRadius = px(r).toFloat()
        if (stroke != null) setStroke(px(1), stroke)
    }

    private fun box() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        background = rounded(card, 18)
        setPadding(px(14), px(14), px(14), px(14))
    }

    private fun field(hintText: String, value: String?, password: Boolean) = EditText(this).apply {
        hint = hintText; setText(value); setTextColor(ink); setHintTextColor(muted); textSize = 15f
        background = rounded(Color.parseColor("#133C4E"), 12)
        setPadding(px(12), px(10), px(12), px(10))
        inputType = if (password) InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        else InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        textDirection = View.TEXT_DIRECTION_LTR
    }

    private fun pill(label: String, primary: Boolean, onClick: () -> Unit) = Button(this).apply {
        text = label; isAllCaps = false; textSize = 14f
        setTextColor(if (primary) Color.parseColor("#04211C") else ink)
        background = if (primary) rounded(accent, 26) else rounded(Color.TRANSPARENT, 26, accent)
        stateListAnimator = null
        setOnClickListener { onClick() }
    }

    private fun hint(s: String) {
        list.removeAllViews()
        list.addView(text(s, 13f, muted).apply { setPadding(px(4), px(12), px(4), px(12)) })
    }

    private fun section(title: String) = runOnUiThread {
        list.addView(text(title, 15f, accent, bold = true).apply { setPadding(px(4), px(16), px(4), px(6)) })
    }

    /** One row: label, connection result, speed bar. Returns its setters. */
    private inner class Row(label: String, lab: Boolean) {
        val view = LinearLayout(this@MainActivity).apply {
            orientation = LinearLayout.VERTICAL
            background = rounded(card, 14)
            setPadding(px(12), px(10), px(12), px(10))
        }
        private val top = LinearLayout(this@MainActivity).apply { orientation = LinearLayout.HORIZONTAL }
        private val name = text((if (lab) "🧪 " else "") + label, 14f, ink)
        private val result = text("در صف", 13f, muted).apply { gravity = Gravity.END }
        private val bar = FrameLayout(this@MainActivity).apply { background = rounded(Color.parseColor("#133C4E"), 4) }
        private val fill = View(this@MainActivity).apply { background = rounded(accent, 4) }

        init {
            top.addView(name, LinearLayout.LayoutParams(0, -2, 1f))
            top.addView(result, LinearLayout.LayoutParams(-2, -2))
            view.addView(top)
            bar.addView(fill, FrameLayout.LayoutParams(0, -1))
            view.addView(bar, LinearLayout.LayoutParams(-1, px(6)).apply { topMargin = px(8) })
            bar.visibility = View.GONE
        }

        fun set(s: String, color: Int) = runOnUiThread { result.text = s; result.setTextColor(color) }
        fun speed(mbps: Double, max: Double) = runOnUiThread {
            bar.visibility = View.VISIBLE
            bar.post {
                fill.layoutParams = FrameLayout.LayoutParams((bar.width * (mbps / max).coerceIn(0.0, 1.0)).toInt(), -1)
            }
        }
    }

    private fun addRow(label: String, lab: Boolean): Row {
        val r = Row(label, lab)
        runOnUiThread {
            list.addView(r.view, LinearLayout.LayoutParams(-1, -2).apply { topMargin = px(6) })
        }
        return r
    }

    // ---------------------------------------------------------------- servers

    /** The published servers: the newest app config (GitHub mirror), else the bundled one. */
    private fun loadPublished() {
        published = decode(runCatching { assets.open("app_config.signed.json").bufferedReader().readText() }.getOrNull())
        showStatus()
        thread {
            for (u in listOf("https://raw.githubusercontent.com/taghvamohammad-art/pv-config/main/config.txt",
                "https://cdn.jsdelivr.net/gh/taghvamohammad-art/pv-config@main/config.txt")) {
                val got = decode(runCatching { get(u) }.getOrNull())
                if (got.length() > 0) {
                    published = got
                    runOnUiThread { showStatus() }
                    break
                }
            }
        }
    }

    private fun get(url: String): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = 8000; c.readTimeout = 8000
        return c.inputStream.bufferedReader().use { it.readText() }
    }

    private fun decode(signed: String?): JSONArray = runCatching {
        val payload = JSONObject(signed!!).getString("payload")
        val cfg = JSONObject(String(Base64.decode(payload, Base64.DEFAULT)))
        cfg.optJSONArray("linux_servers") ?: JSONArray()
    }.getOrDefault(JSONArray())

    private fun labItems(): JSONArray = runCatching { JSONArray(prefs.getString("lab", "[]")) }.getOrDefault(JSONArray())

    /** What gets tested: each published server, with its lab protocols when known; lab-only servers too. */
    private fun items(): List<JSONObject> {
        val labs = labItems()
        val byHost = (0 until labs.length()).map { labs.getJSONObject(it) }
            .associateBy { it.optJSONObject("server")?.optString("host").orEmpty() }
        val out = mutableListOf<JSONObject>()
        val seen = mutableSetOf<String>()
        for (i in 0 until published.length()) {
            val s = published.getJSONObject(i)
            val host = s.optString("host")
            seen += host
            out += JSONObject().put("name", s.optString("name")).put("server", s)
                .put("lab", byHost[host]?.optJSONArray("lab") ?: JSONArray())
        }
        for ((host, it) in byHost) if (host !in seen) out += it   // a new server, not published yet
        return out
    }

    private fun showStatus() {
        val its = items()
        val labs = its.sumOf { it.optJSONArray("lab")?.length() ?: 0 }
        status.text = "سرورها: " + (if (its.isEmpty()) "—" else its.joinToString("، ") { it.optString("name") }) +
            (if (labs > 0) " · $labs پروتکل آزمایشی" else "") + "\n" + network()
    }

    private fun handleShare(intent: Intent) {
        if (intent.action == Intent.ACTION_SEND) importText(intent.getStringExtra(Intent.EXTRA_TEXT).orEmpty())
    }

    private fun clipText(): String {
        val cm = getSystemService(ClipboardManager::class.java)
        return cm.primaryClip?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
    }

    private fun importText(text: String) {
        val servers = try {
            val j = JSONObject(text.trim())
            if (!j.has("pv_test")) throw IllegalArgumentException()
            j.getJSONArray("servers")
        } catch (_: Exception) {
            toast("اول در ابزار انتشار «🧪 پروتکل‌های آزمایشی + خروجی برای اپ تست» را بزنید و متن را کپی کنید.")
            return
        }
        prefs.edit().putString("lab", servers.toString()).apply()
        showStatus()
        toast("پروتکل‌های آزمایشی ${servers.length()} سرور اضافه شد.")
    }

    private fun network(): String {
        val cm = getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        return "شبکه: " + when {
            caps == null -> "بدون اینترنت"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "⚠ VPN روشن است؛ اول قطعش کنید"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                "موبایل " + runCatching { getSystemService(TelephonyManager::class.java).networkOperatorName }.getOrDefault("")
            else -> "?"
        }
    }

    // ---------------------------------------------------------------- the test

    private fun line(s: String) {
        synchronized(report) { report.append(s).append('\n') }
    }

    private data class Item(val server: JSONObject, val test: JSONObject, val name: String, val row: Row)
    private data class Done(val server: String, val label: String, val ms: Int, val mbps: Double)

    private fun run() {
        val its = items()
        if (its.isEmpty()) return toast("سروری پیدا نشد؛ اینترنت را بررسی کنید.")
        val u = user.text.toString().trim()
        val p = pass.text.toString()
        prefs.edit().putString("user", u).putString("pass", p).apply()
        running = true
        stop = false
        start.text = "توقف"
        synchronized(report) { report.setLength(0) }
        list.removeAllViews()
        showStatus()
        thread {
            val now = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
            line("Persian VPN — تست سرورها · $now · ${network()}")
            if (u.isEmpty()) line("(بدون نام کاربری: فقط پروتکل‌های آزمایشی)")
            val queue = mutableListOf<Item>()
            for (item in its) {
                val name = item.optString("name")
                section("$name — اتصال")
                val tests = JSONArray(Pvcore.benchList(item.toString()))
                for (k in 0 until tests.length()) {
                    val t = tests.getJSONObject(k)
                    val lab = t.optString("id").startsWith("lab:")
                    if (!lab && u.isEmpty()) continue
                    if (t.optString("id") == "pool") continue   // made from the ones that connect, below
                    queue += Item(item, t, name, addRow(t.optString("label"), lab))
                }
            }
            // 1) does each connect
            line("\n۱) اتصال")
            val passed = mutableListOf<Item>()
            for (q in queue) {
                if (stop) break
                q.row.set("در حال تست…", warn)
                val r = JSONObject(Pvcore.benchRun(q.server.toString(), q.test.getString("id"), u, p, 0))
                val label = q.test.optString("label")
                if (r.optBoolean("ok")) {
                    val s = "${r.optInt("ms")}ms (${r.optInt("got")}/${r.optInt("tries")})"
                    q.row.set("✓ $s", accent)
                    line("✓ ${q.name} · $label · $s")
                    passed += q
                } else {
                    q.row.set("✗ ${r.optString("error")}", bad)
                    line("✗ ${q.name} · $label · ${r.optString("error")}")
                }
            }
            // the pool as the app makes it: the Xray protocols that connected
            val okKinds = passed.map { it.test.getString("id") }
                .filter { !it.startsWith("lab:") && !it.startsWith("awg@") && !it.startsWith("cdn#") && it != "vless-dns" && !it.startsWith("pool") }
                .distinct()
            if (okKinds.isNotEmpty() && !stop) {
                val first = passed.first { !it.test.getString("id").startsWith("lab:") }
                val t = JSONObject().put("id", "pool:" + okKinds.joinToString(","))
                    .put("label", "مجموعه‌ی Xray از وصل‌شده‌ها (مثل اپ)")
                val row = addRow(t.getString("label"), false)
                val r = JSONObject(Pvcore.benchRun(first.server.toString(), t.getString("id"), u, p, 0))
                if (r.optBoolean("ok")) {
                    row.set("✓ ${r.optInt("ms")}ms (${r.optInt("got")}/${r.optInt("tries")})", accent)
                    passed += Item(first.server, t, first.name, row)
                    line("✓ ${first.name} · ${t.getString("label")} · ${r.optInt("ms")}ms")
                } else {
                    row.set("✗ ${r.optString("error")}", bad)
                    line("✗ ${first.name} · ${t.getString("label")} · ${r.optString("error")}")
                }
            }
            // 2) the speed of those that connected
            val done = mutableListOf<Done>()
            if (passed.isNotEmpty() && !stop) line("\n۲) سرعت (دانلود ۸ ثانیه)")
            var max = 1.0
            for (q in passed) {
                if (stop) break
                q.row.set("سرعت…", warn)
                val r = JSONObject(Pvcore.benchRun(q.server.toString(), q.test.getString("id"), u, p, 8))
                val mbps = r.optDouble("mbps", 0.0)
                val ms = r.optInt("ms")
                val err = r.optString("error")
                max = maxOf(max, mbps)
                q.row.set("%.1f Mbit/s · %dms".format(Locale.US, mbps, ms) + if (err.isNotEmpty()) " ⚠" else "",
                    if (mbps > 0) accent else warn)
                done += Done(q.name, q.test.optString("label"), ms, mbps)
                line("%s · %s · %.1f Mbit/s · %.1f MB%s".format(Locale.US, q.name, q.test.optString("label"), mbps,
                    r.optDouble("mb", 0.0), if (err.isNotEmpty()) " ($err)" else ""))
                passed.forEachIndexed { i, x -> if (i < done.size) x.row.speed(done[i].mbps, max) }
            }
            // 3) best first
            if (done.isNotEmpty()) {
                section("رتبه‌بندی (سریع‌ترین اول)")
                line("\n۳) رتبه‌بندی")
                done.sortedByDescending { it.mbps }.forEachIndexed { i, d ->
                    val s = "%d. %s · %s · %.1f Mbit/s · %dms".format(Locale.US, i + 1, d.server, d.label, d.mbps, d.ms)
                    line(s)
                    runOnUiThread { list.addView(text(s, 13f, if (i < 3) accent else ink).apply { setPadding(px(4), px(3), px(4), px(3)) }) }
                }
            }
            line(if (stop) "\n— متوقف شد —" else "\n— پایان —")
            running = false
            runOnUiThread { start.text = "شروع تست" }
        }
    }

    private fun copyReport() {
        getSystemService(ClipboardManager::class.java).setPrimaryClip(ClipData.newPlainText("test", report.toString()))
        toast("کپی شد")
    }

    private fun shareReport() {
        startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"; putExtra(Intent.EXTRA_TEXT, report.toString())
        }, "ارسال گزارش"))
    }

    private fun toast(s: String) = runOnUiThread { Toast.makeText(this, s, Toast.LENGTH_LONG).show() }
}
