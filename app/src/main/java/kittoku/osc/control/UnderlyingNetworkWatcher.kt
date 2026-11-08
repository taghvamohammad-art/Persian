package kittoku.osc.control

import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.Handler
import android.os.Looper


/**
 * Branded build: reconnects as soon as the phone's real network changes
 * (Wi-Fi <-> mobile data, Wi-Fi off when the screen sleeps, ...).
 *
 * The SSTP socket stays tied to the network it was opened on; after a switch
 * it carries nothing, and without this the engine only noticed through its
 * echo timeout. This app is excluded from its own tunnel, so for this process
 * the "default network" is the physical one, never the VPN.
 */
internal class UnderlyingNetworkWatcher(
    private val manager: ConnectivityManager,
    private val onChanged: () -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private var current: Network? = null
    private var closed = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            handler.post { handle(network) }
        }
    }

    private val fire = Runnable {
        if (!closed) onChanged()
    }

    private fun handle(network: Network) {
        if (closed) return
        val previous = current
        current = network
        if (previous == null || previous == network) return
        // short debounce: networks often flap while switching
        handler.removeCallbacks(fire)
        handler.postDelayed(fire, 1_500)
    }

    internal fun start() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
        current = manager.activeNetwork
        try {
            manager.registerDefaultNetworkCallback(callback)
        } catch (_: Exception) { }
    }

    internal fun close() {
        if (closed) return
        closed = true
        handler.removeCallbacks(fire)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            try {
                manager.unregisterNetworkCallback(callback)
            } catch (_: Exception) { }
        }
    }
}
