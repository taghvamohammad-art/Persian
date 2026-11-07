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
class ExcludedAppsActivity : AppCompatActivity() {
    private data class AppRow(val packageName: String, val label: String)

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
        setSupportActionBar(binding.toolbar)
        title = getString(R.string.brand_excluded_title)
        supportActionBar?.setDisplayHomeAsUpEnabled(true)

        prefs = PreferenceManager.getDefaultSharedPreferences(this)
        selected.addAll(BrandSession.excludedApps(prefs))
        initialSelection = selected.toSet()

        binding.excludedList.adapter = adapter
        binding.excludedList.setOnItemClickListener { _, _, position, _ ->
            val pkg = shown[position].packageName
            if (!selected.remove(pkg)) selected.add(pkg)
            BrandSession.setExcludedApps(prefs, selected)
            adapter.notifyDataSetChanged()
        }

        binding.excludedSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: Editable?) = applyFilter()
        })

        io.execute {
            val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
            val collator = Collator.getInstance(Locale.forLanguageTag("fa"))
            val apps = packageManager.queryIntentActivities(launcher, 0)
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
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == android.R.id.home) {
            finish()
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    override fun finish() {
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
