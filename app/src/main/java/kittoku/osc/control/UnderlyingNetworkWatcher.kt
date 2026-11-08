package kittoku.osc.control

import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Handler
import android.os.Looper


/**
 * Branded build: reconnects when the physical network the tunnel rides on
 * goes away (Wi-Fi off when the screen sleeps, leaving Wi-Fi for mobile
 * data, ...), instead of sitting "connected" until the echo timeout.
 *
 * Only a LOST network triggers a reconnect. A first version also reacted to
 * any "new default network" and, on some phones, saw the VPN itself as a
 * change right after connecting, which caused an endless reconnect loop
 * (2026-11-08). VPN networks are ignored entirely here.
 */
internal class UnderlyingNetworkWatcher(
    private val manager: ConnectivityManager,
    private val onLost: () -> Unit,
) {
    private val handler = Handler(Looper.getMainLooper())
    private var current: Network? = null
    private var closed = false

    private val fire = Runnable {
        if (!closed) onLost()
    }

    private fun isVpn(network: Network): Boolean = try {
        manager.getNetworkCapabilities(network)?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
    } catch (_: Exception) {
        false
    }

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            handler.post {
                // remember the physical network we are on; never the VPN
                if (!closed && current == null && !isVpn(network)) current = network
            }
        }

        override fun onLost(network: Network) {
            handler.post {
                if (closed || network != current) return@post
                current = null
                // short delay: let the replacement network come up first
                handler.removeCallbacks(fire)
                handler.postDelayed(fire, 1_500)
            }
        }
    }

    internal fun start() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return
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
