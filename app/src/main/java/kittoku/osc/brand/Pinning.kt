package kittoku.osc.brand

import android.annotation.SuppressLint
import android.util.Log
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager


/**
 * Trusts a server only if one certificate in its chain has a SHA-256
 * fingerprint listed in [pins] (the leaf, or the CA that signed it).
 *
 * The router's certificates are issued by its own CA and carry an old IP as
 * their name, so normal CA/hostname validation cannot work; the pin is the
 * whole check. With [allowAny] it accepts everything (used only for fetching
 * the signed config, whose content is verified separately).
 */
@SuppressLint("CustomX509TrustManager", "TrustAllX509TrustManager")
internal class PinningTrustManager(
    pins: List<String>,
    private val allowAny: Boolean = false,
) : X509TrustManager {
    private val pinSet = pins.map { it.replace(":", "").lowercase() }.toSet()

    @Volatile internal var lastSeenFingerprints: List<String> = emptyList()
        private set

    override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        throw CertificateException("client certificates are not used")
    }

    override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
        if (allowAny) return
        if (chain.isNullOrEmpty()) throw CertificateException("empty certificate chain")

        val seen = chain.map { sha256Hex(it.encoded) }
        lastSeenFingerprints = seen
        if (seen.none { it in pinSet }) {
            Log.w(BRAND_TAG, "certificate pin mismatch, server sent: $seen")
            throw CertificateException("certificate pin mismatch")
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
}

internal object Pinning {
    internal fun sslContext(pins: List<String>, allowAnyWhenEmpty: Boolean = false): SSLContext {
        val tm = PinningTrustManager(pins, allowAny = allowAnyWhenEmpty && pins.isEmpty())
        return SSLContext.getInstance("TLS").also {
            it.init(null, arrayOf<TrustManager>(tm), null)
        }
    }

    /** The pin replaces hostname checking (certificates name an old IP). */
    internal fun apply(conn: HttpsURLConnection, pins: List<String>, allowAnyWhenEmpty: Boolean = false) {
        conn.sslSocketFactory = sslContext(pins, allowAnyWhenEmpty).socketFactory
        conn.hostnameVerifier = javax.net.ssl.HostnameVerifier { _, _ -> true }
    }
}
