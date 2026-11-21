package kittoku.osc.brand

import android.app.UiModeManager
import android.content.Context
import android.content.pm.PackageManager
import android.content.res.Configuration
import android.view.View

/** Android TV: the same app, driven by the remote (D-pad) on a wide screen. */
internal object Tv {
    fun isTv(context: Context): Boolean {
        val ui = context.getSystemService(Context.UI_MODE_SERVICE) as? UiModeManager
        if (ui?.currentModeType == Configuration.UI_MODE_TYPE_TELEVISION) return true
        val pm = context.packageManager
        return pm.hasSystemFeature(PackageManager.FEATURE_LEANBACK) ||
            !pm.hasSystemFeature(PackageManager.FEATURE_TOUCHSCREEN)
    }

    /** Keep the phone layout as a centred column instead of stretching it across the TV. */
    fun centre(content: View, maxWidthDp: Int = 560) {
        val ctx = content.context
        if (!isTv(ctx)) return
        val dm = ctx.resources.displayMetrics
        val widthDp = dm.widthPixels / dm.density
        if (widthDp <= maxWidthDp + 32) return
        val side = (((widthDp - maxWidthDp) / 2) * dm.density).toInt()
        content.setPadding(side, content.paddingTop, side, content.paddingBottom)
    }
}
