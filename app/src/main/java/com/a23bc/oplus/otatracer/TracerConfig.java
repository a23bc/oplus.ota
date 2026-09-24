package com.a23bc.oplus.otatracer;

/**
 * Targets and thresholds for the tracer.
 *
 * Everything is best-effort: if a class/method is absent on a given ROM the tracer
 * logs once and moves on. Nothing here is required for the OTA app to work.
 */
public final class TracerConfig {

    /** Only these packages get hooked. com.oplus.ota:ui shares this package name. */
    public static final String TARGET_PACKAGE = "com.oplus.ota";

    // ---------------------------------------------------------------- classes

    /**
     * Guessed FQCNs for the signing helper; obfuscated builds fall back to scanning.
     * The com.oplus.ota.downloader.* entries come from a real trace: the dex scan
     * found com.oplus.ota.downloader.util.SignVerifyUtils$ByteArrayComparator,
     * which pins the outer class name.
     */
    public static final String[] SIGN_VERIFY_CLASS_CANDIDATES = {
            "com.oplus.ota.downloader.util.SignVerifyUtils",
            "com.oplus.ota.downloader.SignVerifyUtils",
            "com.oplus.ota.utils.SignVerifyUtils",
            "com.oplus.ota.common.utils.SignVerifyUtils",
            "com.oplus.ota.util.SignVerifyUtils",
            "com.oplus.ota.security.SignVerifyUtils",
            "com.oplus.ota.sign.SignVerifyUtils",
            "com.oplus.ota.gka.SignVerifyUtils",
            "com.oplus.ota.SignVerifyUtils",
    };

    public static final String[] GET_INFO_THREAD_CANDIDATES = {
            "com.oplus.ota.downloader.GetInfoThread",
            "com.oplus.ota.downloader.thread.GetInfoThread",
            "com.oplus.ota.downloader.util.GetInfoThread",
            "com.oplus.ota.module.GetInfoThread",
            "com.oplus.ota.thread.GetInfoThread",
            "com.oplus.ota.net.GetInfoThread",
            "com.oplus.ota.utils.GetInfoThread",
            "com.oplus.ota.GetInfoThread",
    };

    public static final String[] DOWNLOAD_EXCEPTION_CANDIDATES = {
            "com.oplus.ota.downloader.DownloadException",
            "com.oplus.ota.exception.DownloadException",
            "com.oplus.ota.common.exception.DownloadException",
            "com.oplus.ota.net.DownloadException",
            "com.oplus.ota.module.DownloadException",
            "com.oplus.ota.DownloadException",
            "com.oplus.ota.download.DownloadException",
    };

    // ---------------------------------------------------------------- methods

    /** SignVerifyUtils methods we care about (name-only match, all overloads). */
    public static final String[] SIGN_VERIFY_METHODS = {
            "getGkaReqDownloadType",
            "ecdsaSignPki",
            "ecdsaSign",
            "signPki",
    };

    /** Method-name substrings interesting inside GetInfoThread. */
    public static final String[] GET_INFO_METHOD_HINTS = {
            "download", "request", "getinfo", "getInfo", "gka", "http", "url", "response",
    };

    /** SharedPreferences keys worth echoing (int values only, not secrets). */
    public static final String[] SP_KEY_HINTS = {
            "gka", "gak", "reqdownload", "downloadtype", "download_type", "sign", "type",
    };

    /** Log lines echoed from the app itself; keeps volume low on purpose. */
    public static final String[] LOG_MSG_HINTS = {
            "download denied", "ecdsasignpki", "gkareq", "responsecode", "errormsg",
            "downloadexception", "signverify", "2304",
    };

    public static final String[] LOG_TAG_HINTS = {
            "signverify", "getinfothread", "download", "gka", "ota", "update", "verify",
    };

    /** Cap on how many methods of one class we hook, keeps log volume sane. */
    public static final int MAX_METHODS_PER_CLASS = 12;

    /** Stack frames printed per call site. */
    public static final int STACK_DEPTH = 14;

    // ---------------------------------------------------------------- switches
    //
    // Bisection aids: if the OTA process ever hangs again, flip these to false
    // one at a time to find the culprit without uninstalling the module.

    /** Hooks on shared classes: HttpURLConnection, KeyStore, SharedPreferences, Log. */
    public static final boolean ENABLE_SHARED_CLASS_HOOKS = true;

    /** Echo of the app's own log lines (android.util.Log is a very hot method). */
    public static final boolean ENABLE_LOG_ECHO = true;

    /** Background dex scans (keyword + deep method-name scan). */
    public static final boolean ENABLE_DEX_SCAN = true;

    // ------------------------------------------------------------ scheduling
    //
    // All discovery work runs off the main thread and is rate limited. The :ui
    // process hung once when class loading itself was hooked; keep it that way.

    /** Keyword dex scan start delay (main thread does nothing but schedule it). */
    public static final int DEX_SCAN_DELAY_MS = 3000;

    /** Method-name deep scan start delay, only if SignVerifyUtils is unresolved. */
    public static final int DEEP_SCAN_DELAY_MS = 9000;

    /** Yield after every N loaded classes during the deep scan. */
    public static final int DEEP_SCAN_BATCH = 60;

    /** Hard wall-clock budget for the deep scan. */
    public static final int DEEP_SCAN_BUDGET_MS = 15000;

    /** Sleep between scan batches, keeps the app responsive. */
    public static final long SCAN_YIELD_MS = 15L;

    /** Heartbeat lines, so a hang can be located by its last seq. */
    public static final int HEARTBEAT_COUNT = 12;
    public static final int HEARTBEAT_INTERVAL_MS = 5000;

    /** Cap on echoed app log lines per second (Log is a very hot method). */
    public static final int LOG_ECHO_MAX_PER_SEC = 25;

    private TracerConfig() {
    }
}
