package kittoku.osc.brand

import android.util.Base64
import java.security.MessageDigest


/**
 * Encoding of the signed config on the public mirror (GitHub pv-config).
 *
 * "PVC1:" + base64(nonce[16] || ciphertext); the keystream is
 * SHA-256(KEY || nonce || counter_be32) per 32-byte block. Same scheme as
 * tools/release_tool/publisher.py (encode_public).
 *
 * This only keeps server addresses from being readable or scraped from a
 * public file; anyone with the APK can find the key. Authenticity comes
 * from the signature inside, which is checked after decoding.
 */
internal object ConfigCodec {
    private const val PREFIX = "PVC1:"
    private val KEY = hex("76eb86bc2d0bea3f596d86ce523e008f442ef27675478a7f61719792ef083d02")

    private fun hex(s: String) = ByteArray(s.length / 2) { s.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** Returns the plain signed envelope; text without the prefix is returned as-is. */
    internal fun decodeIfNeeded(text: String): String {
        val t = text.trim()
        if (!t.startsWith(PREFIX)) return t
        val raw = Base64.decode(t.substring(PREFIX.length), Base64.DEFAULT)
        if (raw.size < 16) throw IllegalArgumentException("short")
        val nonce = raw.copyOfRange(0, 16)
        val out = ByteArray(raw.size - 16)
        val md = MessageDigest.getInstance("SHA-256")
        var block = 0
        var i = 0
        while (i < out.size) {
            md.reset()
            md.update(KEY)
            md.update(nonce)
            md.update(byteArrayOf((block ushr 24).toByte(), (block ushr 16).toByte(),
                (block ushr 8).toByte(), block.toByte()))
            val ks = md.digest()
            var j = 0
            while (j < 32 && i < out.size) {
                out[i] = (raw[16 + i].toInt() xor ks[j].toInt()).toByte()
                i++
                j++
            }
            block++
        }
        return String(out, Charsets.UTF_8)
    }
}
