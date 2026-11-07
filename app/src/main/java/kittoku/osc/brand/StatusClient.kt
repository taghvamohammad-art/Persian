package kittoku.osc.brand

import android.util.Log
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import javax.net.ssl.HttpsURLConnection


@Serializable
internal data class CurrentProfile(
    val profile: String = "",
    val display: String = "",
    val start: String? = null,
    val end: String? = null,
    @SerialName("seconds_left") val secondsLeft: Long? = null,
    @SerialName("days_left") val daysLeft: Long? = null,
    @SerialName("used_bytes") val usedBytes: Long = 0,
    @SerialName("limit_bytes") val limitBytes: Long? = null,
    @SerialName("remaining_bytes") val remainingBytes: Long? = null,
)

@Serializable
internal data class NextProfile(
    val profile: String = "",
    val display: String = "",
    @SerialName("validity_days") val validityDays: Long? = null,
    @SerialName("limit_bytes") val limitBytes: Long? = null,
)

/** Response of umstatus POST /v1/status. */
@Serializable
internal data class AccountStatus(
    val ok: Boolean = false,
    val username: String = "",
    val state: String = "",          // active, volume_finished, expired, waiting, no_profile
    val current: CurrentProfile? = null,
    val next: List<NextProfile> = emptyList(),
    val disabled: Boolean = false,
    @SerialName("server_time") val serverTime: String = "",
)

internal sealed class StatusResult {
    data class Ok(val status: AccountStatus) : StatusResult()
    object InvalidCredentials : StatusResult()
    object TooManyAttempts : StatusResult()
    object ServerProblem : StatusResult()   // router or service error
    object Unreachable : StatusResult()     // network / filtering / pin mismatch
}

internal object StatusClient {
    /** Network I/O: call off the main thread. */
    internal fun fetch(config: AppConfig, username: String, password: String): StatusResult {
        val body = buildJsonObject {
            put("username", username)
            put("password", password)
        }.toString().toByteArray(Charsets.UTF_8)

        var result: StatusResult = StatusResult.Unreachable
        for (url in config.statusUrls) {
            result = try {
                post(url, config.statusPins, body)
            } catch (e: IOException) {
                Log.w(BRAND_TAG, "status request failed at $url: $e")
                StatusResult.Unreachable
            }
            if (result !is StatusResult.Unreachable && result !is StatusResult.ServerProblem) {
                return result
            }
        }
        return result
    }

    private fun post(url: String, pins: List<String>, body: ByteArray): StatusResult {
        val conn = URL(url).openConnection() as HttpURLConnection
        if (conn is HttpsURLConnection) {
            Pinning.apply(conn, pins)
        }
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.connectTimeout = 10_000
        conn.readTimeout = 40_000   // first request of a recharged user can take ~10 s
        conn.setRequestProperty("Content-Type", "application/json")

        try {
            conn.outputStream.use { it.write(body) }
            val code = conn.responseCode
            val text = (if (code < 400) conn.inputStream else conn.errorStream)
                ?.bufferedReader()?.use { it.readText() } ?: ""

            return when (code) {
                200 -> StatusResult.Ok(brandJson.decodeFromString(AccountStatus.serializer(), text))
                401 -> StatusResult.InvalidCredentials
                429 -> StatusResult.TooManyAttempts
                else -> {
                    val err = runCatching {
                        brandJson.decodeFromString(JsonObject.serializer(), text)["error"]?.jsonPrimitive?.content
                    }.getOrNull()
                    Log.w(BRAND_TAG, "status HTTP $code ($err)")
                    StatusResult.ServerProblem
                }
            }
        } finally {
            conn.disconnect()
        }
    }
}
