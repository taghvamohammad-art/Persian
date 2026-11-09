package kittoku.osc.brand

import android.content.Context
import android.content.SharedPreferences
import kittoku.osc.R
import kittoku.osc.preference.AUTH_PROTOCOL_MSCHAPv2
import kittoku.osc.preference.LIST_TYPE_DISALLOWED
import kittoku.osc.preference.OscPrefKey
import kittoku.osc.preference.accessor.getStringPrefValue


/**
 * Glue between the branded UI and the original Open SSTP Client engine,
 * which reads all of its settings from SharedPreferences.
 */
internal object BrandSession {
    internal const val PREF_LAST_ERROR = "BRAND_LAST_ERROR"
    internal const val PREF_LOGGED_IN = "BRAND_LOGGED_IN"
    internal const val PREF_LAST_STATUS = "BRAND_LAST_STATUS"

    // A stale session stays on the router until SSTP keepalive (60 s) ends it,
    // and the user may hold only one session (shared-users=1). Reconnecting
    // too fast makes the router drop one of the two, so wait a bit.
    // 40 tries x 15 s: keeps trying for about 10 minutes, long enough for a
    // phone that wakes up, changes network, or waits for a stale session.
    private const val RECONNECT_INTERVAL_SECONDS = 15
    private const val RECONNECT_COUNT = 40

    internal fun isLoggedIn(prefs: SharedPreferences): Boolean =
        prefs.getBoolean(PREF_LOGGED_IN, false)

    internal fun username(prefs: SharedPreferences): String =
        getStringPrefValue(OscPrefKey.HOME_USERNAME, prefs)

    internal fun password(prefs: SharedPreferences): String =
        getStringPrefValue(OscPrefKey.HOME_PASSWORD, prefs)

    internal fun login(prefs: SharedPreferences, username: String, password: String) {
        prefs.edit()
            .putString(OscPrefKey.HOME_USERNAME.name, username)
            .putString(OscPrefKey.HOME_PASSWORD.name, password)
            .putBoolean(PREF_LOGGED_IN, true)
            .remove(PREF_LAST_ERROR)
            .remove(PREF_LAST_STATUS)
            .apply()
    }

    internal fun logout(prefs: SharedPreferences) {
        prefs.edit()
            .putString(OscPrefKey.HOME_USERNAME.name, "")
            .putString(OscPrefKey.HOME_PASSWORD.name, "")
            .putBoolean(PREF_LOGGED_IN, false)
            .remove(PREF_LAST_ERROR)
            .remove(PREF_LAST_STATUS)
            .apply()
    }

    /** Writes every engine setting this app depends on, before each connect. */
    internal fun applyEngineSettings(prefs: SharedPreferences, server: ServerEntry) {
        prefs.edit()
            .putString(OscPrefKey.HOME_HOSTNAME.name, server.host)
            .putString(OscPrefKey.SSL_PORT.name, server.port.toString())   // engine stores ints as strings
            .putString(OscPrefKey.SSL_VERSION.name, "DEFAULT")
            // trust is decided by the pinned fingerprints (see SSLTerminal)
            .putBoolean(OscPrefKey.SSL_DO_VERIFY.name, false)
            .putBoolean(OscPrefKey.SSL_DO_SPECIFY_CERT.name, false)
            .putBoolean(OscPrefKey.SSL_DO_SELECT_SUITES.name, false)
            .putBoolean(OscPrefKey.SSL_DO_USE_CUSTOM_SNI.name, false)
            .putBoolean(OscPrefKey.PROXY_DO_USE_PROXY.name, false)
            // the router offers pap/chap/mschap1/mschap2; never send the password in clear
            .putStringSet(OscPrefKey.PPP_AUTH_PROTOCOLS.name, setOf(AUTH_PROTOCOL_MSCHAPv2))
            .putBoolean(OscPrefKey.PPP_IPv4_ENABLED.name, true)
            .putBoolean(OscPrefKey.PPP_IPv6_ENABLED.name, false)
            .putBoolean(OscPrefKey.DNS_DO_REQUEST_ADDRESS.name, true)
            .putBoolean(OscPrefKey.ROUTE_DO_ADD_DEFAULT_ROUTE.name, true)
            // apps the user chose to keep outside the VPN (e.g. banking apps)
            .putBoolean(OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE.name, excludedApps(prefs).isNotEmpty())
            .putString(OscPrefKey.ROUTE_APP_LIST_TYPE.name, LIST_TYPE_DISALLOWED)
            .putBoolean(OscPrefKey.RECONNECTION_ENABLED.name, true)
            .putString(OscPrefKey.RECONNECTION_COUNT.name, RECONNECT_COUNT.toString())
            .putString(OscPrefKey.RECONNECTION_INTERVAL.name, RECONNECT_INTERVAL_SECONDS.toString())
            .putBoolean(OscPrefKey.LOG_DO_SAVE_LOG.name, false)
            .remove(PREF_LAST_ERROR)
            .commit()
    }

    /** Package names kept outside the tunnel. Stored where the engine reads them. */
    internal fun excludedApps(prefs: SharedPreferences): Set<String> =
        prefs.getStringSet(OscPrefKey.ROUTE_SELECTED_APPS.name, null) ?: emptySet()

    internal fun setExcludedApps(prefs: SharedPreferences, packages: Set<String>) {
        prefs.edit()
            .putStringSet(OscPrefKey.ROUTE_SELECTED_APPS.name, packages.toSet())
            .putBoolean(OscPrefKey.ROUTE_DO_ENABLE_APP_BASED_RULE.name, packages.isNotEmpty())
            .putString(OscPrefKey.ROUTE_APP_LIST_TYPE.name, LIST_TYPE_DISALLOWED)
            .apply()
    }

    internal fun recordError(prefs: SharedPreferences, header: String) {
        prefs.edit().putString(PREF_LAST_ERROR, header).apply()
    }

    /** Persian text for an engine error header such as "OSC: ERR_UNEXPECTED". */
    internal fun describeError(context: Context, header: String): String = when {
        header.contains("ERR_AUTHENTICATION_FAILED") -> context.getString(R.string.brand_vpn_err_auth)
        header.startsWith("CERT") -> context.getString(R.string.brand_vpn_err_cert)
        header.contains("ERR_TIMEOUT") -> context.getString(R.string.brand_vpn_err_timeout)
        header.contains("ERR_CONNECTION_LOST") -> context.getString(R.string.brand_vpn_err_lost)
        else -> context.getString(R.string.brand_vpn_err_generic, header)
    }

    private const val PREF_ERROR_DETAIL = "BRAND_ERROR_DETAIL"

    /** Keeps the last error with its stack trace for the "last error report" screen. */
    internal fun recordErrorDetail(prefs: SharedPreferences, header: String, detail: String) {
        val time = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.US)
            .format(java.util.Date())
        prefs.edit().putString(PREF_ERROR_DETAIL,
            "$time  $header\nversion ${kittoku.osc.BuildConfig.VERSION_NAME} " +
            "(${kittoku.osc.BuildConfig.VERSION_CODE}), Android ${android.os.Build.VERSION.RELEASE}\n\n" +
            detail.take(4000)).apply()
    }

    internal fun errorDetail(prefs: SharedPreferences): String? =
        prefs.getString(PREF_ERROR_DETAIL, null)

    internal fun clearError(prefs: SharedPreferences) {
        prefs.edit().remove(PREF_LAST_ERROR).apply()
    }

    internal fun lastError(prefs: SharedPreferences): String? =
        prefs.getString(PREF_LAST_ERROR, null)

    internal fun saveStatus(prefs: SharedPreferences, status: AccountStatus) {
        prefs.edit().putString(PREF_LAST_STATUS,
            brandJson.encodeToString(AccountStatus.serializer(), status)).apply()
    }

    internal fun savedStatus(prefs: SharedPreferences): AccountStatus? =
        prefs.getString(PREF_LAST_STATUS, null)?.let {
            runCatching { brandJson.decodeFromString(AccountStatus.serializer(), it) }.getOrNull()
        }
}
