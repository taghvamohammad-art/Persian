package kittoku.osc.brand

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.core.content.FileProvider
import androidx.core.content.pm.PackageInfoCompat
import kittoku.osc.BuildConfig
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection


/**
 * In-app updates. The new APK is downloaded from the router and installed
 * only if its SHA-256 matches the value in the signed config and it is a
 * newer build of this same app. Android always asks the user to confirm
 * the installation; it also has to be signed with the same keystore.
 */
internal object UpdateManager {
    private const val DIR = "updates"           // must match res/xml/update_paths.xml
    private const val FILE = "update.apk"
    private const val MAX_SIZE = 100L * 1024 * 1024

    internal class UpdateException(val reason: Reason) : Exception(reason.name)

    internal enum class Reason { NETWORK, BAD_FILE }

    internal enum class InstallStep { STARTED, NEEDS_PERMISSION }

    internal fun currentVersionCode(): Long = BuildConfig.VERSION_CODE.toLong()

    internal fun available(config: AppConfig?): AppUpdate? =
        config?.appUpdate?.takeIf { it.versionCode > currentVersionCode() && it.urls.isNotEmpty() }

    private fun target(context: Context): File =
        File(File(context.cacheDir, DIR).apply { mkdirs() }, FILE)

    /** The already-downloaded file, if it is exactly [update]. */
    internal fun readyFile(context: Context, update: AppUpdate): File? {
        val f = target(context)
        if (!f.isFile || f.length() != update.size) return null
        return if (sha256File(f) == update.sha256.lowercase() && isNewerBuildOfThisApp(context, f, update)) f else null
    }

    /**
     * Downloads and verifies [update]. Network I/O: call off the main thread.
     * [progress] gets 0..100.
     */
    internal fun download(context: Context, update: AppUpdate, pins: List<String>, progress: (Int) -> Unit): File {
        readyFile(context, update)?.let { return it }
        if (update.size <= 0 || update.size > MAX_SIZE) throw UpdateException(Reason.BAD_FILE)

        val dest = target(context)
        val part = File(dest.parentFile, "$FILE.part")
        var lastError = Reason.NETWORK

        // a few MB instead of the whole app, when this phone has a version we have a patch from
        if (tryPatch(context, update, pins, dest, progress)) return dest

        for (url in update.urls) {
            try {
                fetch(url, pins, part, update.size, progress)
                if (part.length() != update.size || sha256File(part) != update.sha256.lowercase()) {
                    Log.w(BRAND_TAG, "update from $url failed verification")
                    lastError = Reason.BAD_FILE
                    continue
                }
                dest.delete()
                if (!part.renameTo(dest)) throw IOException("rename failed")
                if (!isNewerBuildOfThisApp(context, dest, update)) {
                    dest.delete()
                    lastError = Reason.BAD_FILE
                    continue
                }
                return dest
            } catch (e: IOException) {
                Log.w(BRAND_TAG, "update download failed from $url: $e")
                lastError = Reason.NETWORK
            } finally {
                part.delete()
            }
        }
        throw UpdateException(lastError)
    }

    private fun fetch(url: String, pins: List<String>, out: File, expected: Long, progress: (Int) -> Unit) {
        val conn = URL(url).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) {
            // integrity comes from the signed SHA-256, not from TLS
            Pinning.apply(conn, pins, allowAnyWhenEmpty = true)
        }
        conn.connectTimeout = 15_000
        conn.readTimeout = 30_000
        try {
            if (conn.responseCode != 200) throw IOException("HTTP ${conn.responseCode}")
            conn.inputStream.use { input ->
                out.outputStream().use { output ->
                    val buf = ByteArray(64 * 1024)
                    var total = 0L
                    var lastPct = -1
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > expected) throw IOException("file larger than announced")
                        output.write(buf, 0, n)
                        val pct = (total * 100 / expected).toInt()
                        if (pct != lastPct) {
                            lastPct = pct
                            progress(pct)
                        }
                    }
                }
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun tryPatch(context: Context, update: AppUpdate, pins: List<String>, dest: File,
                         progress: (Int) -> Unit): Boolean {
        if (update.patches.isEmpty()) return false
        val installed = File(context.applicationInfo.sourceDir)
        val mine = try { sha256File(installed) } catch (e: IOException) { return false }
        val patch = update.patches.firstOrNull { it.fromSha256.equals(mine, ignoreCase = true) } ?: return false
        if (patch.size <= 0 || patch.size > MAX_SIZE) return false
        val pfile = File(dest.parentFile, "update.pvdl")
        val part = File(dest.parentFile, "$FILE.part")
        for (url in patch.urls) {
            try {
                fetch(url, pins, pfile, patch.size, progress)
                if (pfile.length() != patch.size || sha256File(pfile) != patch.sha256.lowercase()) continue
                ApkPatcher.apply(installed, pfile, part)
                if (part.length() != update.size || sha256File(part) != update.sha256.lowercase()) {
                    Log.w(BRAND_TAG, "patched APK does not match the signed hash")
                    return false
                }
                dest.delete()
                if (!part.renameTo(dest)) return false
                if (!isNewerBuildOfThisApp(context, dest, update)) {
                    dest.delete()
                    return false
                }
                Log.i(BRAND_TAG, "updated with a ${patch.size} byte patch")
                return true
            } catch (e: IOException) {
                Log.w(BRAND_TAG, "patch from $url failed: $e")
            } finally {
                pfile.delete()
                part.delete()
            }
        }
        return false
    }

    private fun sha256File(f: File): String {
        val md = MessageDigest.getInstance("SHA-256")
        f.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
    }

    /** Guards against a config that names the wrong APK (other app or wrong versionCode). */
    private fun isNewerBuildOfThisApp(context: Context, apk: File, update: AppUpdate): Boolean {
        @Suppress("DEPRECATION")
        val info = context.packageManager.getPackageArchiveInfo(apk.path, 0) ?: return false
        val code = PackageInfoCompat.getLongVersionCode(info)
        val ok = info.packageName == context.packageName &&
                code == update.versionCode && code > currentVersionCode()
        if (!ok) Log.w(BRAND_TAG, "downloaded APK is ${info.packageName} v$code, expected v${update.versionCode}")
        return ok
    }

    /** Opens Android's install screen, or the "install unknown apps" setting first. */
    internal fun install(activity: Activity, apk: File): InstallStep {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !activity.packageManager.canRequestPackageInstalls()) {
            activity.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${activity.packageName}"))
            )
            return InstallStep.NEEDS_PERMISSION
        }

        val intent = Intent(Intent.ACTION_VIEW)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            val uri = FileProvider.getUriForFile(activity, "${activity.packageName}.updates", apk)
            intent.setDataAndType(uri, "application/vnd.android.package-archive")
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        } else {
            // Android 6: the installer cannot read content:// URIs; hand it a
            // world-readable copy in external cache.
            val dir = activity.externalCacheDir ?: activity.cacheDir
            val copy = File(dir, FILE)
            apk.copyTo(copy, overwrite = true)
            @Suppress("SetWorldReadable")
            copy.setReadable(true, false)
            intent.setDataAndType(Uri.fromFile(copy), "application/vnd.android.package-archive")
        }
        activity.startActivity(intent)
        return InstallStep.STARTED
    }
}
