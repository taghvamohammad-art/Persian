package kittoku.osc.brand

import android.content.ClipData
import android.content.ClipboardManager
import android.content.SharedPreferences
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager
import ir.persianvpn.pvcore.Pvcore
import kittoku.osc.R
import kittoku.osc.databinding.ActivityShareBinding


/**
 * Hotspot sharing: a proxy (HTTP and SOCKS5) that devices on this phone's
 * hotspot set in their Wi-Fi settings; everything goes into the VPN tunnel.
 * Android itself does not send hotspot devices through a VPN.
 */
class ShareActivity : AppCompatActivity() {
    private lateinit var binding: ActivityShareBinding
    private lateinit var prefs: SharedPreferences
    private val ui = Handler(Looper.getMainLooper())
    private val tick = object : Runnable {
        override fun run() {
            render()
            ui.postDelayed(this, 2000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityShareBinding.inflate(layoutInflater)
        setContentView(binding.root)
        setSupportActionBar(binding.toolbar)
        title = getString(R.string.brand_share_title)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)
        prefs = PreferenceManager.getDefaultSharedPreferences(this)

        binding.shareHelp.text = getText(R.string.brand_share_help)
        binding.shareSwitch.isChecked = BrandSession.shareEnabled(prefs)
        binding.shareSwitch.setOnCheckedChangeListener { _, on ->
            BrandSession.setShareEnabled(prefs, on)
            if (on) startNow() else runCatching { Pvcore.stopShare() }
            render()
        }
        binding.shareCopy.setOnClickListener {
            val text = binding.shareAddress.text.toString()
            getSystemService(ClipboardManager::class.java)
                .setPrimaryClip(ClipData.newPlainText("proxy", text))
            Toast.makeText(this, R.string.brand_share_copied, Toast.LENGTH_SHORT).show()
        }
    }

    /** VPN already up on an Xray tunnel: start the proxy right away. */
    private fun startNow() {
        val kind = runCatching { Pvcore.running() }.getOrDefault("")
        if (kind.isEmpty() || kind == "amneziawg") return
        val cm = getSystemService(android.net.ConnectivityManager::class.java)
        val uplink = runCatching { cm.getLinkProperties(cm.activeNetwork)?.interfaceName }.getOrNull() ?: ""
        runCatching { Pvcore.startShare(BrandSession.SHARE_PORT.toLong(), uplink) }
    }

    private fun render() {
        val on = BrandSession.shareEnabled(prefs)
        val kind = runCatching { Pvcore.running() }.getOrDefault("")
        val addrs = runCatching { Pvcore.shareAddresses() }.getOrDefault("").trim()
        binding.shareAddressRow.visibility = View.GONE
        binding.shareStatus.setText(
            when {
                !on -> R.string.brand_share_status_off
                kind.isEmpty() -> R.string.brand_share_status_no_vpn
                kind == "amneziawg" -> R.string.brand_share_status_reconnect
                addrs.isEmpty() -> R.string.brand_share_status_no_hotspot
                else -> {
                    binding.shareAddress.text = addrs.lines().first()
                    binding.shareAddressRow.visibility = View.VISIBLE
                    R.string.brand_share_status_ready
                }
            }
        )
    }

    override fun onResume() {
        super.onResume()
        ui.post(tick)
    }

    override fun onPause() {
        ui.removeCallbacks(tick)
        super.onPause()
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }
}
