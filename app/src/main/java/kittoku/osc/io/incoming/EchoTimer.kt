package kittoku.osc.io.incoming

import android.os.SystemClock

// Awake time, not wall time: while the phone sleeps (screen off) the loop
// that reads the echo replies is frozen too, so wall time would declare a
// healthy tunnel dead the moment the phone wakes, before the buffered
// replies are read. uptimeMillis() does not advance during deep sleep.

internal class EchoTimer(private val interval: Long, private val echoFunction: suspend () -> Unit) {
    private var lastTicked = 0L
    private var deadline = 0L

    private var isEchoWaited = false

    private val isOutOfTime: Boolean
        get() = SystemClock.uptimeMillis() - lastTicked > interval

    private val isDead: Boolean
        get() = SystemClock.uptimeMillis() > deadline

    internal suspend fun checkAlive(): Boolean {
        if (isOutOfTime) {
            if (isEchoWaited) {
                if (isDead) {
                    return false
                }
            } else {
                echoFunction.invoke()
                isEchoWaited = true
                deadline = SystemClock.uptimeMillis() + interval
            }
        }

        return true
    }

    internal fun tick() {
        lastTicked = SystemClock.uptimeMillis()
        isEchoWaited = false
    }
}
