package kittoku.osc.control

import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.BufferedOutputStream
import java.io.OutputStream
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale


/** The last lines of the connection log, kept in memory for the test screen
 * (DiagnosticsActivity) whether or not saving the log to a file is on. */
internal object DiagLog {
    private const val MAX = 300
    private val lines = ArrayDeque<String>()

    @Synchronized fun add(line: String) {
        lines.addLast(line)
        while (lines.size > MAX) lines.removeFirst()
    }

    @Synchronized fun all(): List<String> = lines.toList()
}

/** The connection log: always in memory (DiagLog), in a file when the user chose one. */
internal class LogWriter(logOutput: OutputStream?) {
    private val mutex = Mutex()
    private val outputStream = logOutput?.let { BufferedOutputStream(it) }
    private val currentTime: String
        get() = SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS", Locale.getDefault()).format(Date())

    internal fun write(message: String) {
        // use directly if it's cannot be race condition, like onCreate and onDestroy
        val line = "[$currentTime] $message"
        DiagLog.add(line)
        runCatching { outputStream?.write("$line\n".toByteArray(Charsets.UTF_8)) }
    }

    internal suspend fun report(message: String) {
        mutex.withLock { write(message) }
    }

    internal fun close() {
        runCatching {
            outputStream?.flush()
            outputStream?.close()
        }
    }
}
