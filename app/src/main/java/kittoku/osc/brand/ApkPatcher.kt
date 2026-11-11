package kittoku.osc.brand

import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.File
import java.io.IOException
import java.io.RandomAccessFile
import java.util.zip.GZIPInputStream


/**
 * Rebuilds the new APK from the installed one and a patch made by the
 * release tool (tools/release_tool/apkdelta.py): unchanged parts are
 * copied from the installed APK, the rest comes in the patch. The caller
 * checks the result against the signed SHA-256.
 */
internal object ApkPatcher {
    private val MAGIC = "PVDL1\n".toByteArray()

    internal fun apply(old: File, patch: File, out: File) {
        RandomAccessFile(old, "r").use { base ->
            DataInputStream(GZIPInputStream(patch.inputStream().buffered(), 64 * 1024)).use { input ->
                val magic = ByteArray(MAGIC.size)
                input.readFully(magic)
                if (!magic.contentEquals(MAGIC)) throw IOException("not a patch")
                BufferedOutputStream(out.outputStream(), 256 * 1024).use { output ->
                    val buf = ByteArray(256 * 1024)
                    while (true) {
                        when (input.readUnsignedByte().toChar()) {
                            'C' -> {
                                val off = input.readLong()
                                var left = input.readLong()
                                if (off < 0 || left < 0 || off + left > base.length()) throw IOException("bad copy")
                                base.seek(off)
                                while (left > 0) {
                                    val n = base.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
                                    if (n < 0) throw IOException("short base")
                                    output.write(buf, 0, n)
                                    left -= n
                                }
                            }
                            'D' -> {
                                var left = input.readInt()
                                if (left < 0) throw IOException("bad data")
                                while (left > 0) {
                                    val n = input.read(buf, 0, minOf(buf.size, left))
                                    if (n < 0) throw IOException("short patch")
                                    output.write(buf, 0, n)
                                    left -= n
                                }
                            }
                            'E' -> return
                            else -> throw IOException("bad patch")
                        }
                    }
                }
            }
        }
    }
}
