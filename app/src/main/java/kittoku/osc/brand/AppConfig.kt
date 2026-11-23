package kittoku.osc.brand

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import android.util.Log
import androidx.preference.PreferenceManager
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.HttpURLConnection
import java.net.URL
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import javax.net.ssl.HttpsURLConnection


internal const val BRAND_TAG = "Brand"

@Serializable
internal data class ServerEntry(
    val name: String = "",
    val host: String,
    val port: Int = 443,
)

/**
 * Server settings. Signed by the owner's offline key (tools/sign_config.py);
 * the app never trusts an unsigned or lower-version config.
 */
@Serializable
internal data class AppConfig(
    val version: Int,
    val servers: List<ServerEntry>,
    @SerialName("sstp_pins") val sstpPins: List<String> = emptyList(),
    @SerialName("status_urls") val statusUrls: List<String> = emptyList(),
    @SerialName("status_pins") val statusPins: List<String> = emptyList(),
    @SerialName("config_urls") val configUrls: List<String> = emptyList(),
    @SerialName("config_pins") val configPins: List<String> = emptyList(),
    @SerialName("app_update") val appUpdate: AppUpdate? = null,
    // a test build, offered only to the usernames whose tester hash is listed
    @SerialName("app_update_beta") val appUpdateBeta: AppUpdate? = null,
    // Xray / AmneziaWG servers (tools/release_tool/linux.py server_entry);
    // kept as raw JSON and handed to the pvcore engine as is
    @SerialName("linux_servers") val linuxServers: List<kotlinx.serialization.json.JsonObject> = emptyList(),
)

/** Newest app release. Its SHA-256 is covered by the config signature. */
@Serializable
internal data class AppUpdate(
    @SerialName("version_code") val versionCode: Long,
    @SerialName("version_name") val versionName: String = "",
    val urls: List<String> = emptyList(),
    val sha256: String,
    val size: Long,
    val notes: String = "",
    // small updates: rebuild the new APK from the installed one
    val patches: List<ApkPatch> = emptyList(),
    // test builds: sha256("pv-tester\n" + username)[:16] of each tester
    val testers: List<String> = emptyList(),
    // «آپدیت اجباری»: versions below this cannot connect until they update
    @SerialName("min_version_code") val minVersionCode: Long = 0,
)

internal fun testerHash(username: String): String =
    sha256Hex(("pv-tester\n" + username.trim().lowercase()).toByteArray()).take(16)

@Serializable
internal data class ApkPatch(
    @SerialName("from_sha256") val fromSha256: String,
    val sha256: String,
    val size: Long,
    val urls: List<String> = emptyList(),
)

@Serializable
private data class Envelope(val payload: String, val sig: String)

internal val brandJson = Json { ignoreUnknownKeys = true }

internal fun sha256Hex(data: ByteArray): String {
    return MessageDigest.getInstance("SHA-256").digest(data)
        .joinToString("") { "%02x".format(it.toInt() and 0xff) }
}

internal object ConfigManager {
    private const val ASSET_CONFIG = "app_config.signed.json"
    private const val ASSET_PUBKEY = "config_key.public.txt"
    private const val PREF_CACHED = "BRAND_CONFIG_ENVELOPE"

    @Volatile private var cached: AppConfig? = null

    private fun prefs(context: Context): SharedPreferences =
        PreferenceManager.getDefaultSharedPreferences(context)

    private fun publicKeyBytes(context: Context): ByteArray {
        val text = context.assets.open(ASSET_PUBKEY).bufferedReader().use { it.readText() }
        return Base64.decode(text.trim(), Base64.DEFAULT)
    }

    /** Returns the config inside [envelopeText] if its signature is valid. */
    internal fun verify(envelopeText: String, publicKeyDer: ByteArray): AppConfig? {
        return try {
            val env = brandJson.decodeFromString(Envelope.serializer(), envelopeText)
            val payload = Base64.decode(env.payload, Base64.DEFAULT)
            val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(publicKeyDer))
            val ok = Signature.getInstance("SHA256withECDSA").run {
                initVerify(key)
                update(payload)
                verify(Base64.decode(env.sig, Base64.DEFAULT))
            }
            if (!ok) {
                Log.w(BRAND_TAG, "config signature invalid")
                null
            } else {
                brandJson.decodeFromString(AppConfig.serializer(), String(payload, Charsets.UTF_8))
            }
        } catch (e: Exception) {
            Log.w(BRAND_TAG, "config rejected: $e")
            null
        }
    }

    /** Newest valid config: the one shipped in the APK or a newer downloaded one. */
    @Synchronized
    internal fun current(context: Context): AppConfig {
        cached?.let { return it }

        val pub = publicKeyBytes(context)
        val builtIn = context.assets.open(ASSET_CONFIG).bufferedReader().use { it.readText() }
            .let { verify(it, pub) }
            ?: throw IllegalStateException("built-in config is missing or not signed with the built-in key")

        val stored = prefs(context).getString(PREF_CACHED, null)?.let { verify(it, pub) }

        val best = if (stored != null && stored.version > builtIn.version) stored else builtIn
        cached = best
        return best
    }

    internal enum class InstallResult { INSTALLED, NOT_NEWER, INVALID }

    /**
     * Keeps [envelopeText] if it is signed with the built-in key and newer
     * than the current config. Used for downloads and for manual import
     * (a file sent to users, e.g. through a Telegram channel, when the old
     * server is gone). An older version is refused so a stale file cannot
     * roll users back to a dead server.
     */
    internal fun install(context: Context, envelopeText: String): Pair<InstallResult, AppConfig?> {
        // the public mirror (and a file shared from it) is encoded; the router serves it plain
        val plain = try {
            ConfigCodec.decodeIfNeeded(envelopeText)
        } catch (e: Exception) {
            return InstallResult.INVALID to null
        }
        val cfg = verify(plain, publicKeyBytes(context))
            ?: return InstallResult.INVALID to null
        synchronized(this) {
            val cur = current(context)
            if (cfg.version <= cur.version) return InstallResult.NOT_NEWER to cur
            prefs(context).edit().putString(PREF_CACHED, plain).commit()
            cached = cfg
        }
        Log.i(BRAND_TAG, "config updated to version ${cfg.version}")
        return InstallResult.INSTALLED to cfg
    }

    /**
     * Downloads the config from the URLs of the current config and keeps it
     * if it is validly signed and newer. Runs network I/O: call off the main thread.
     * Returns true when a newer config was installed.
     */
    internal fun refresh(context: Context): Boolean {
        val cur = current(context)

        for (url in cur.configUrls) {
            try {
                val text = httpGet(url, cur.configPins) ?: continue
                when (install(context, text).first) {
                    InstallResult.INSTALLED -> return true
                    InstallResult.NOT_NEWER -> return false
                    InstallResult.INVALID -> continue
                }
            } catch (e: Exception) {
                Log.w(BRAND_TAG, "config fetch failed from $url: $e")
            }
        }
        return false
    }

    private fun httpGet(url: String, pins: List<String>): String? {
        val conn = URL(url).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) {
            // The content is signed, so any TLS certificate is acceptable here
            // unless the config asks for pinning.
            Pinning.apply(conn, pins, allowAnyWhenEmpty = true)
        }
        conn.connectTimeout = 8_000
        conn.readTimeout = 8_000
        return try {
            if (conn.responseCode != 200) null
            else conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }
}
