package kittoku.osc.brand

import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.MenuItem
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.preference.PreferenceManager
import kittoku.osc.R
import kittoku.osc.databinding.ActivityExcludedAppsBinding
import kittoku.osc.databinding.ItemExcludedAppBinding
import java.text.Collator
import java.util.Locale
import java.util.concurrent.Executors


/** Lets the user keep chosen apps (e.g. banking apps) outside the tunnel. */
/**
 * The app list, in two modes: "outside the VPN" (default) and «سپر VPN»
 * (EXTRA_SHIELD: apps that may use the internet only through the VPN).
 * An app is never in both lists.
 */
class ExcludedAppsActivity : AppCompatActivity() {
    companion object {
        const val EXTRA_SHIELD = "shield"
    }

    private data class AppRow(val packageName: String, val label: String)
    private var shieldMode = false

    private fun mine(): Set<String> =
        if (shieldMode) BrandSession.shieldedApps(prefs) else BrandSession.excludedApps(prefs)

    private fun other(): Set<String> =
        if (shieldMode) BrandSession.excludedApps(prefs) else BrandSession.shieldedApps(prefs)

    private fun save() {
        if (shieldMode) {
            BrandSession.setShieldedApps(prefs, selected)
            val ex = BrandSession.excludedApps(prefs)
            if (ex.any { it in selected }) {
                BrandSession.setExcludedApps(prefs, ex - selected)
                Toast.makeText(this, R.string.brand_shield_moved, Toast.LENGTH_SHORT).show()
            }
            // the service closes or opens the shield right away while the VPN is not connected
            Shield.refresh(this)
        } else {
            BrandSession.setExcludedApps(prefs, selected)
        }
    }

    private val askVpn = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()
    ) {
        Shield.refresh(this)
        super@ExcludedAppsActivity.finish()
    }

    private lateinit var binding: ActivityExcludedAppsBinding
    private lateinit var prefs: SharedPreferences
    private val io = Executors.newSingleThreadExecutor()

    private var allApps: List<AppRow> = emptyList()
    private var shown: List<AppRow> = emptyList()
    private val selected = mutableSetOf<String>()
    private var initialSelection: Set<String> = emptySet()

    private val adapter = object : BaseAdapter() {
        override fun getCount() = shown.size
        override fun getItem(position: Int) = shown[position]
        override fun getItemId(position: Int) = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val item = if (convertView == null) {
                ItemExcludedAppBinding.inflate(layoutInflater, parent, false).also { it.root.tag = it }
            } else {
                convertView.tag as ItemExcludedAppBinding
            }
            val row = shown[position]
            item.appLabel.text = row.label
            item.appCheck.isChecked = row.packageName in selected
            item.appIcon.setImageDrawable(
                try {
                    packageManager.getApplicationIcon(row.packageName)
                } catch (_: PackageManager.NameNotFoundException) {
                    null
                }
            )
            return item.root
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityExcludedAppsBinding.inflate(layoutInflater)
        setContentView(binding.root)
        Tv.centre(binding.root)
        setSupportActionBar(binding.toolbar)
        shieldMode = intent.getBooleanExtra(EXTRA_SHIELD, false)
        title = getString(if (shieldMode) R.string.brand_shield_title else R.string.brand_excluded_title)
        if (shieldMode) {
            binding.excludedHelp.text = getString(R.string.brand_shield_help) + "\n\n" +
                getString(R.string.brand_shield_always_on)
            binding.excludedHelp.setOnClickListener {
                try {
                    startActivity(Intent(android.provider.Settings.ACTION_VPN_SETTINGS))
                } catch (_: Exception) {
                }
            }
        }
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        selected.addAll(mine())
        initialSelection = selected.toSet()

        binding.excludedList.adapter = adapter
        binding.excludedList.setOnItemClickListener { _, _, position, _ ->
            val pkg = shown[position].packageName
            if (!shieldMode && pkg !in selected && pkg in other()) {
                Toast.makeText(this, R.string.brand_shield_in_other, Toast.LENGTH_SHORT).show()
                return@setOnItemClickListener
            }
            if (!selected.remove(pkg)) selected.add(pkg)
            save()
            adapter.notifyDataSetChanged()
            syncAll()
        }

        // "select all": every app in the list (only the ones found while searching)
        binding.excludedAll.setOnClickListener {
            val blocked = if (shieldMode) emptySet() else other()
            val pkgs = shown.map { it.packageName }.filter { it !in blocked }
            if (binding.excludedAll.isChecked) selected.addAll(pkgs) else selected.removeAll(pkgs.toSet())
            save()
            adapter.notifyDataSetChanged()
        }

        binding.excludedSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = applyFilter()
        })

        io.execute {
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val tvLauncher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LEANBACK_LAUNCHER)
            val collator = Collator.getInstance(Locale.forLanguageTag("fa"))
            val apps = (packageManager.queryIntentActivities(launcher, 0) +
                        packageManager.queryIntentActivities(tvLauncher, 0))   // TV apps
                .map { it.activityInfo.applicationInfo }
                .distinctBy { it.packageName }
                .filter { it.packageName != packageName }
                .map { AppRow(it.packageName, packageManager.getApplicationLabel(it).toString()) }
                // chosen apps first, then alphabetical
                .sortedWith(compareBy<AppRow> { it.packageName !in selected }
                    .thenComparator { a, b -> collator.compare(a.label, b.label) })

            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                allApps = apps
                binding.excludedProgress.visibility = View.GONE
                binding.excludedList.visibility = View.VISIBLE
                binding.excludedAll.visibility = View.VISIBLE
                applyFilter()
            }
        }
    }

    private fun applyFilter() {
        val q = binding.excludedSearch.text?.toString()?.trim().orEmpty()
        shown = if (q.isEmpty()) allApps else allApps.filter {
            it.label.contains(q, ignoreCase = true) || it.packageName.contains(q, ignoreCase = true)
        }
        adapter.notifyDataSetChanged()
        binding.excludedAll.setText(if (q.isEmpty()) R.string.brand_excluded_all else R.string.brand_excluded_all_found)
        syncAll()
    }

    private fun syncAll() {
        binding.excludedAll.isChecked = shown.isNotEmpty() && shown.all { it.packageName in selected }
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    override fun finish() {
        if (shieldMode) {
            // the shield needs the VPN permission even while the VPN is off
            val ask = if (selected.isNotEmpty()) android.net.VpnService.prepare(this) else null
            if (ask != null && selected != initialSelection) {
                initialSelection = selected.toSet()
                try {
                    askVpn.launch(ask)
                    return
                } catch (_: Exception) {
                }
            }
            super.finish()
            return
        }
        if (selected != initialSelection) {
            Toast.makeText(this, R.string.brand_excluded_apply, Toast.LENGTH_LONG).show()
        }
        super.finish()
    }

    override fun onDestroy() {
        io.shutdown()
        super.onDestroy()
    }
}
