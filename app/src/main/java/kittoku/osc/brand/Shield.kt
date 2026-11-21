package kittoku.osc.brand

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import androidx.core.content.ContextCompat
import androidx.preference.PreferenceManager
import kittoku.osc.service.ACTION_VPN_SHIELD
import kittoku.osc.service.SstpVpnService

/**
 * «سپر VPN»: chosen apps may use the internet only through the VPN.
 * While the real tunnel is not up, SstpVpnService keeps an empty VPN for
 * just those apps and drops their packets (see SstpVpnService.startShield).
 */
internal object Shield {
    fun apps(context: Context): Set<String> =
        BrandSession.shieldedApps(PreferenceManager.getDefaultSharedPreferences(context))

    /** Tell the service the list changed (or the phone started): it closes or opens the shield. */
    fun refresh(context: Context) {
        if (VpnService.prepare(context) != null) return        // no VPN permission yet
        val intent = Intent(context, SstpVpnService::class.java).setAction(ACTION_VPN_SHIELD)
        try {
            if (apps(context).isEmpty()) context.startService(intent)
            else ContextCompat.startForegroundService(context, intent)
        } catch (_: Exception) {
            // not allowed to start from the background just now; the next connect or boot applies it
        }
    }
}

/** After a reboot or an update the shield is closed again before anything else runs. */
class ShieldBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED ||
            intent.action == "android.intent.action.QUICKBOOT_POWERON"
        ) {
            if (Shield.apps(context).isNotEmpty()) Shield.refresh(context)
        }
    }
}
