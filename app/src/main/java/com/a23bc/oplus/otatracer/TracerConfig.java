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

    // ----------------------------------------------------------- repair mode
    //
    // Diagnosis is closed: AndroidKeyStore has no EC key under "ota_pki_attest"
    // and the app carries on with a null key. Repair mode fills in the missing
    // key material right after the app itself discovers the alias is absent.
    //
    // This is NOT a signature bypass: no return value is rewritten, no argument
    // is touched, no exception is swallowed. Signing runs exactly as before -
    // it just has a real key to work with. Whether the server accepts the newly
    // generated key's certificate is the open question.

    /**
     * r14: OFF on purpose. The module must be purely observational again so the
     * attestation chain can be read without anything of ours in it.
     *
     * This does NOT change the flow. r11 proved the repair was already inert:
     * when containsAlias("ota_pki_attest") returned false the SDK was inside its
     * own attestation path, so KeyRepair logged "deferring to SDK attestation
     * flow" and did nothing; the key came from
     * android.provider.BeandCupClalt.createApplicationPublicKey and getKey()
     * then returned a real AndroidKeyStoreECPrivateKey. So switching this off
     * costs no observation and removes the last thing that could inject.
     */
    public static final boolean ENABLE_KEY_REPAIR = false;

    /** Aliases we are willing to create when the app reports them missing. */
    public static final String[] REPAIR_ALIASES = {"ota_pki_attest"};

    /** EC curve for the generated key (the app asks for SHA256withECDSA). */
    public static final String REPAIR_EC_CURVE = "secp256r1";

    /**
     * Last resort. If the keystore still reports no key after generation, hand
     * the generated private key to getKey() so signing can proceed at all.
     * The signature is produced normally and the server still verifies it; we
     * only supply the missing key material. Turn off to keep the module purely
     * observational.
     */
    public static final boolean ENABLE_KEY_INJECT = true;

    /**
     * Classes whose real name is known from a stack trace but whose methods are
     * obfuscated. Resolved from the r4 trace: ecdsaSignPki is
     * com.oplus.ota.downloader.util.b.d(), getGkaReqDownloadType is b.i(), and
     * the "SignVerifyUtils" name in the dex is an empty shell that throws
     * ClassNotFoundException. For these we hook every declared method.
     */
    public static final String[] SIGN_VERIFY_EXACT_CLASSES = {
            "com.oplus.ota.downloader.util.b",
    };

    /**
     * The PKI SDK's attestation helper, seen in the getKey() stack:
     *   com.allawn...AttestationUtil.deleteKeyIfExists
     *   com.allawn...AttestationUtil.createApplicationPublicKey
     * It is not obfuscated, so it can be watched directly. Whatever it does (or
     * silently fails to do) explains why no attestation key ever existed.
     */
    public static final String[] ATTESTATION_CLASSES = {
            "com.allawn.cryptography.security.attestation.AttestationUtil",
            "com.allawn.cryptography.security.attestation.AttestationManager",
    };

    /**
     * Library prefixes, used to tell app code from bundled dependencies when the
     * class name alone cannot (obfuscated top-level packages like u7.a).
     */
    public static final String[] LIBRARY_PREFIXES = {
            "android.", "androidx.", "com.android.", "java.", "javax.", "kotlin.",
            "kotlinx.", "dalvik.", "org.", "com.google.", "com.squareup.", "okhttp3.",
            "okio.", "org.jetbrains.", "com.tencent.", "com.oplus.anim.",
    };

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

    /**
     * Diagnostic: echo every line from the OTA / PKI tags instead of only the
     * keyword matches. Noisy, but it is the only way to see the context the app
     * itself prints around a server error code like 2713.
     */
    public static final boolean ENABLE_VERBOSE_APPLOG = true;

    /**
     * The attestation flow talks to a CryptoEng HAL service, and the device logs
     * "cryptoeng_hidl: process com.oplus.ota have no permission calling cmd:10009".
     * Dump the SDK's own command enum so those numbers mean something.
     */
    public static final String[] CRYPTO_CMD_TYPE_CLASSES = {
            "com.allawn.cryptography.teesdk.type.CryptoEngCmdType",
            "com.allawn.cryptography.teesdk.type.CryptoengCmdType",
    };

    /** Class-name keywords for finding the CryptoEng client. */
    public static final String[] CRYPTO_ENG_KEYWORDS = {"cryptoeng", "cryptoEng"};

    public static final int CRYPTO_ENG_MAX_CLASSES = 6;
    public static final int CRYPTO_ENG_MAX_METHODS = 10;
    public static final int CRYPTO_ENG_SCAN_DELAY_MS = 4000;

    // ------------------------------------------------- r14: parse / verdict chain
    //
    // r13 pinned the chain up to the CryptoEng answer:
    //   pkiCommonAsk() -> byte[2512] -> ??? -> generate() -> generateX509() = null
    // These three are the checks the SDK runs on that buffer before it decides
    // the answer is usable. r14 records only their verdict: return type, null-ness,
    // boolean value, and the exception class+message if one is thrown.
    // Nothing is rewritten, nothing is injected, no fallback is added.

    /** Guessed FQCNs; the SDK is com.allawn.cryptography.* and unobfuscated. */
    public static final String[] PARSE_DIAG_CLASS_CANDIDATES = {
            "com.allawn.cryptography.teesdk.util.ResultParser",
            "com.allawn.cryptography.teesdk.result.ResultParser",
            "com.allawn.cryptography.util.ResultParser",
            "com.allawn.cryptography.ResultParser",
            "com.allawn.cryptography.teesdk.util.Util",
            "com.allawn.cryptography.util.Util",
            "com.allawn.cryptography.teesdk.Util",
    };

    /** Fallback lookup when the FQCN guesses miss: exact simple-name match. */
    public static final String[] PARSE_DIAG_SIMPLE_NAMES = {"ResultParser", "Util"};

    /** The only methods hooked by r14. Everything else stays untouched. */
    public static final String[] PARSE_DIAG_METHODS = {
            "parse", "isParseSuccess", "isMethodExecuteSuccessV2",
    };

    public static final int PARSE_DIAG_MAX_CLASSES = 4;
    public static final int PARSE_DIAG_SCAN_DELAY_MS = 5000;

    /** Caller stacks printed per "this check failed" verdict; keeps volume sane. */
    public static final int PARSE_DIAG_MAX_VERDICT_STACKS = 12;

    // ------------------------------------------- gkaReq=2 download observation
    //
    // Why the final download answer is 2713. Observation only: nothing here
    // rewrites a header, a URL, a body or a signature input.

    /** The signing helper's request builder: a(HttpURLConnection, Context, String, int). */
    public static final int GKA_REQ_DOWNLOAD = 2;

    /** Classes holding the /ts answer JSON: {"id":..,"ts":..,"uri":..}. */
    public static final String[] TS_JSON_CLASSES = {"p5.b"};

    /** Method on those classes that returns the JSON. */
    public static final String[] TS_JSON_METHODS = {"t"};

    /** Substrings that mark a URL as belonging to the OTA backend. */
    public static final String[] DOWNLOAD_URL_HINTS = {"allawntech", "component-ota"};

    /**
     * The one endpoint whose real HTTP status matters. The OTA app's own
     * "responseCode=2713" is a field inside the response body, not an HTTP
     * status - the two must not be confused when reading the log.
     */
    public static final String DOWNLOAD_ENDPOINT = "https://component-ota-cn.allawntech.com/download";

    /** Path fragment of the download endpoint. */
    public static final String[] DOWNLOAD_ENDPOINT_PATHS = {"/download"};

    /** Request headers printed verbatim: identifiers, not secrets. */
    public static final String[] HEADER_KEYS_PLAIN = {"id", "ts"};

    /** Request headers printed as length + SHA-256 only: signature material. */
    public static final String[] HEADER_KEYS_HASHED = {"ac", "as"};

    /** Captured response bodies are truncated at this many characters. */
    public static final int MAX_BODY_CHARS = 4000;

    /** Tags always echoed when verbose logging is on. */
    public static final String[] VERBOSE_LOG_TAGS = {
            "OTAApplication", "Attestation", "allawn", "pki", "Crypto", "GetInfoThread",
    };

    private TracerConfig() {
    }
}
