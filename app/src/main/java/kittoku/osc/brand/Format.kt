package kittoku.osc.brand

import java.util.Locale


internal object Fa {
    private val digits = charArrayOf('۰', '۱', '۲', '۳', '۴', '۵', '۶', '۷', '۸', '۹')

    /** Replaces ASCII digits with Persian ones and '.' with the Persian decimal sign. */
    internal fun digits(s: String): String {
        val sb = StringBuilder(s.length)
        for (c in s) {
            sb.append(
                when (c) {
                    in '0'..'9' -> digits[c - '0']
                    '.' -> '٫'
                    else -> c
                }
            )
        }
        return sb.toString()
    }

    /** Bytes as gigabytes with one decimal, the unit the plans are sold in. */
    internal fun gb(bytes: Long): String {
        val gib = bytes / (1024.0 * 1024.0 * 1024.0)
        val text = if (gib >= 100) String.format(Locale.US, "%.0f", gib)
                   else String.format(Locale.US, "%.1f", gib).removeSuffix(".0")
        return digits(text)
    }

    private val jalaliMonths = arrayOf(
        "فروردین", "اردیبهشت", "خرداد", "تیر", "مرداد", "شهریور",
        "مهر", "آبان", "آذر", "دی", "بهمن", "اسفند",
    )

    /** Gregorian -> Jalali (year, month 1..12, day). */
    internal fun toJalali(gy: Int, gm: Int, gd: Int): Triple<Int, Int, Int> {
        val gdm = intArrayOf(0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334)
        val gy2 = if (gm > 2) gy + 1 else gy
        var days = 355666 + 365 * gy + (gy2 + 3) / 4 - (gy2 + 99) / 100 +
                (gy2 + 399) / 400 + gd + gdm[gm - 1]
        var jy = -1595 + 33 * (days / 12053)
        days %= 12053
        jy += 4 * (days / 1461)
        days %= 1461
        if (days > 365) {
            jy += (days - 1) / 365
            days = (days - 1) % 365
        }
        val jm: Int
        val jd: Int
        if (days < 186) {
            jm = 1 + days / 31
            jd = 1 + days % 31
        } else {
            jm = 7 + (days - 186) / 30
            jd = 1 + (days - 186) % 30
        }
        return Triple(jy, jm, jd)
    }

    /** "2026-12-05 19:19:16" -> "۱۴ آذر ۱۴۰۵، ۱۹:۱۹" (router local time). */
    internal fun dateTime(routerTime: String?): String? {
        if (routerTime == null) return null
        val m = Regex("""(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})""").find(routerTime) ?: return null
        val (y, mo, d, h, mi) = m.destructured
        val (jy, jm, jd) = toJalali(y.toInt(), mo.toInt(), d.toInt())
        return digits("$jd ${jalaliMonths[jm - 1]} $jy، $h:$mi")
    }
}
