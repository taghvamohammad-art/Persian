package ir.persianvpn.tester

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Bundle
import android.telephony.TelephonyManager
import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import ir.persianvpn.pvcore.Pvcore
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlin.concurrent.thread

/**
 * Tests every protocol, and every way of each, of the servers in the
 * release tool's export («خروجی برای اپ تست»): first whether each connects
 * (three requests), then the speed of the ones that did (a download of a few
 * seconds), and at the end the fastest first. No VPN: the engine connects
 * by itself.
 */
class MainActivity : AppCompatActivity() {
    private lateinit var user: EditText
    private lateinit var pass: EditText
    private lateinit var info: TextView
    private lateinit var out: TextView
    private lateinit var scroll: ScrollView
    private lateinit var start: Button
    @Volatile private var running = false
    @Volatile private var stop = false
    private val report = StringBuilder()

    private val prefs by lazy { getSharedPreferences("tester", MODE_PRIVATE) }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.decorView.layoutDirection = View.LAYOUT_DIRECTION_RTL
        val pad = (12 * resources.displayMetrics.density).toInt()
        val root = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL; setPadding(pad, pad, pad, pad) }
        user = EditText(this).apply {
            hint = "نام کاربری (برای پروتکل‌های اصلی)"; setText(prefs.getString("user", ""))
            inputType = InputType.TYPE_CLASS_TEXT
        }
        pass = EditText(this).apply {
            hint = "رمز"; setText(prefs.getString("pass", ""))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
        }
        info = TextView(this).apply { setPadding(0, pad / 2, 0, pad / 2) }
        val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        val paste = Button(this).apply { text = "چسباندن سرورها"; setOnClickListener { importText(clipText()) } }
        start = Button(this).apply { text = "شروع تست"; setOnClickListener { if (running) stop = true else run() } }
        val copy = Button(this).apply { text = "کپی گزارش"; setOnClickListener { copyReport() } }
        val share = Button(this).apply { text = "ارسال"; setOnClickListener { shareReport() } }
        listOf(paste, start, copy, share).forEach {
            row.addView(it, LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f))
        }
        out = TextView(this).apply {
            typeface = Typeface.MONOSPACE; textSize = 12f; setTextIsSelectable(true)
            textDirection = View.TEXT_DIRECTION_LTR
        }
        scroll = ScrollView(this).apply { addView(out) }
        root.addView(user)
        root.addView(pass)
        root.addView(row)
        root.addView(info)
        root.addView(scroll, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        setContentView(root)
        intent?.let { handleShare(it) }
        showServers()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleShare(intent)
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
            toast("این متن خروجی «اپ تست» ابزار انتشار نیست.")
            return
        }
        prefs.edit().putString("servers", servers.toString()).apply()
        showServers()
        toast("${servers.length()} سرور وارد شد.")
    }

    private fun servers(): JSONArray = runCatching { JSONArray(prefs.getString("servers", "[]")) }.getOrDefault(JSONArray())

    private fun showServers() {
        val s = servers()
        val names = (0 until s.length()).map { s.getJSONObject(it).optString("name") }
        info.text = if (names.isEmpty()) "سرورها: هنوز وارد نشده (از ابزار انتشار «خروجی برای اپ تست» را کپی کنید)"
        else "سرورها: ${names.joinToString("، ")}\n${network()}"
    }

    private fun network(): String {
        val cm = getSystemService(ConnectivityManager::class.java)
        val caps = cm.getNetworkCapabilities(cm.activeNetwork)
        val kind = when {
            caps == null -> "بدون اینترنت"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "VPN روشن است! (اول قطعش کنید)"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "Wi-Fi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ->
                "موبایل " + runCatching { getSystemService(TelephonyManager::class.java).networkOperatorName }.getOrDefault("")
            else -> "?"
        }
        return "شبکه: $kind"
    }

    private fun line(s: String) {
        report.append(s).append('\n')
        runOnUiThread {
            out.text = report
            scroll.post { scroll.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private data class Done(val server: String, val label: String, val ms: Int, val mbps: Double)

    private fun run() {
        val list = servers()
        if (list.length() == 0) return toast("اول سرورها را وارد کنید.")
        prefs.edit().putString("user", user.text.toString().trim()).putString("pass", pass.text.toString()).apply()
        val u = user.text.toString().trim()
        val p = pass.text.toString()
        running = true
        stop = false
        start.text = "توقف"
        report.setLength(0)
        thread {
            val now = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date())
            line("Persian VPN — تست سرورها · $now · ${network()}")
            if (u.isEmpty()) line("(بدون نام کاربری: فقط پروتکل‌های آزمایشی تست می‌شوند)")
            val passed = mutableListOf<Triple<JSONObject, JSONObject, String>>()   // server, test, server name
            // 1) does each connect
            for (i in 0 until list.length()) {
                val item = list.getJSONObject(i)
                val name = item.optString("name")
                line("\n━━ $name — ۱) اتصال")
                val tests = JSONArray(Pvcore.benchList(item.toString()))
                for (k in 0 until tests.length()) {
                    if (stop) break
                    val t = tests.getJSONObject(k)
                    val lab = t.optString("id").startsWith("lab:")
                    if (!lab && u.isEmpty()) continue
                    val r = JSONObject(Pvcore.benchRun(item.toString(), t.getString("id"), u, p, 0))
                    val tag = if (lab) "🧪" else "  "
                    if (r.optBoolean("ok")) {
                        line("$tag ✓ ${t.optString("label")}  ${r.optInt("ms")}ms (${r.optInt("got")}/${r.optInt("tries")})")
                        passed += Triple(item, t, name)
                    } else {
                        line("$tag ✗ ${t.optString("label")}  ${r.optString("error")}")
                    }
                }
            }
            // 2) the speed of those that connected
            val done = mutableListOf<Done>()
            if (passed.isNotEmpty() && !stop) line("\n━━ ۲) سرعت (دانلود ۸ ثانیه)")
            for ((item, t, name) in passed) {
                if (stop) break
                val r = JSONObject(Pvcore.benchRun(item.toString(), t.getString("id"), u, p, 8))
                val mbps = r.optDouble("mbps", 0.0)
                val err = r.optString("error")
                line("%s  %-34s %6.1f Mbit/s  %5.1f MB%s".format(Locale.US, name, t.optString("label"), mbps,
                    r.optDouble("mb", 0.0), if (err.isNotEmpty()) "  ($err)" else ""))
                done += Done(name, t.optString("label"), r.optInt("ms"), mbps)
            }
            // 3) best first
            if (done.isNotEmpty()) {
                line("\n━━ ۳) رتبه‌بندی (سریع‌ترین اول)")
                done.sortedByDescending { it.mbps }.forEachIndexed { i, d ->
                    line("%2d. %-10s %-34s %6.1f Mbit/s  %dms".format(Locale.US, i + 1, d.server, d.label, d.mbps, d.ms))
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
