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

    /** Guessed FQCNs for the signing helper; obfuscated builds fall back to scanning. */
    public static final String[] SIGN_VERIFY_CLASS_CANDIDATES = {
            "com.oplus.ota.utils.SignVerifyUtils",
            "com.oplus.ota.common.utils.SignVerifyUtils",
            "com.oplus.ota.util.SignVerifyUtils",
            "com.oplus.ota.security.SignVerifyUtils",
            "com.oplus.ota.sign.SignVerifyUtils",
            "com.oplus.ota.gka.SignVerifyUtils",
            "com.oplus.ota.SignVerifyUtils",
    };

    public static final String[] GET_INFO_THREAD_CANDIDATES = {
            "com.oplus.ota.module.GetInfoThread",
            "com.oplus.ota.thread.GetInfoThread",
            "com.oplus.ota.net.GetInfoThread",
            "com.oplus.ota.utils.GetInfoThread",
            "com.oplus.ota.GetInfoThread",
    };

    public static final String[] DOWNLOAD_EXCEPTION_CANDIDATES = {
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

    private TracerConfig() {
    }
}
