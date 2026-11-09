package kittoku.osc.brand

import java.util.concurrent.atomic.AtomicLong


/**
 * Traffic and duration of the current connection, shown in the ongoing
 * notification. Reset when the user connects; kept across automatic
 * reconnects so the numbers describe the user's whole session.
 */
internal object SessionTraffic {
    internal val downloaded = AtomicLong(0)
    internal val uploaded = AtomicLong(0)

    /** wall-clock ms when the tunnel first came up in this session, 0 = not yet */
    @Volatile internal var connectedSince = 0L

    /** rejected logins while reconnecting; reset when the tunnel comes up */
    @Volatile internal var authFailures = 0

    internal fun reset() {
        authFailures = 0
        downloaded.set(0)
        uploaded.set(0)
        connectedSince = 0L
    }
}
