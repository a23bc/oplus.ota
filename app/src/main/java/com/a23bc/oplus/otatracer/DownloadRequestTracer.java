package com.a23bc.oplus.otatracer;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Observation of the gkaReq=2 download request: what goes out, what comes back.
 *
 * Five things, and only these five:
 *   1. b.a(HttpURLConnection, Context, String, int)  - URL + i9, only when i9 == 2
 *   2. p5.b.t()                                      - the /ts JSON it returns
 *   3. HttpURLConnection.addRequestProperty          - id / ts verbatim, ac / as as
 *                                                      length + SHA-256
 *   4. the /ts response                              - URL, HTTP status, body
 *   5. the final download response                   - URL, HTTP status, body
 *
 * Read-only throughout. No argument, header, return value or throwable is ever
 * rewritten, and the body capture only observes the bytes the app itself reads -
 * it never reads ahead of the app and never hands back a different stream.
 *
 * Scope discipline: every shared-class callback is gated by the existing
 * OtaLog.callerIsTargetApp() stack filter AND by a URL filter built on the
 * existing ResponseCodeTracer.safeUrl(), so no unrelated HTTP traffic in the
 * process is printed.
 */
public final class DownloadRequestTracer {

    private static final String SCOPE = "DlReq";

    private static final String[] CONNECTION_CLASSES = {
            "com.android.okhttp.internal.huc.HttpURLConnectionImpl",
            "java.net.HttpURLConnection",
    };

    private static boolean installed = false;

    private static volatile ClassLoader appCl;

    /** True between b.a(...i9==2) entry and exit, on this thread. */
    private static final ThreadLocal<int[]> IN_GKA_REQUEST = new ThreadLocal<>();

    /** The connection handed to b.a(...i9==2), on this thread. */
    private static final ThreadLocal<Object> GKA_CONN = new ThreadLocal<>();

    /** Real HTTP status last seen for the download endpoint, on this thread. */
    private static final ThreadLocal<Integer> DOWNLOAD_STATUS = new ThreadLocal<>();

    /** The stream currently being read for an OTA endpoint, on this thread. */
    private static final ThreadLocal<Object> TRACKED_STREAM = new ThreadLocal<>();
    private static final ThreadLocal<ByteArrayOutputStream> TRACKED_BODY = new ThreadLocal<>();
    private static final ThreadLocal<String> TRACKED_URL = new ThreadLocal<>();

    private static final Set<String> STREAM_CLASSES =
            Collections.synchronizedSet(new HashSet<>());

    private DownloadRequestTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        appCl = lpparam.classLoader;

        // (1) and (2) are app classes: always installed.
        hookRequestBuilder(lpparam.classLoader);
        hookTsJson(lpparam.classLoader);

        // (3), (4) and (5) touch shared classes: respect the existing switch.
        if (!TracerConfig.ENABLE_SHARED_CLASS_HOOKS) {
            OtaLog.i(SCOPE, "shared class hooks disabled - header/response observation off");
            return;
        }
        hookHeaders();
        hookResponses();
    }

    // ------------------------------------------------------- (1) b.a(..., i9)

    private static void hookRequestBuilder(ClassLoader cl) {
        for (String fqcn : TracerConfig.SIGN_VERIFY_EXACT_CLASSES) {
            Class<?> c;
            try {
                c = XposedHelpers.findClassIfExists(fqcn, cl);
            } catch (Throwable t) {
                c = null;
            }
            if (c == null) {
                OtaLog.i(SCOPE, "no request builder class " + fqcn);
                continue;
            }
            ClassHunter.hookAllByName(c, "a", new GkaReqCallback(), SCOPE);
        }
    }

    private static final class GkaReqCallback extends XC_MethodHook {

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Object[] args = param.args;
                if (args == null || args.length != 4) {
                    return;
                }
                if (!(args[0] instanceof java.net.HttpURLConnection)
                        || !(args[2] instanceof String)
                        || !(args[3] instanceof Integer)) {
                    return;
                }
                int i9 = (Integer) args[3];
                if (i9 != TracerConfig.GKA_REQ_DOWNLOAD) {
                    return;
                }
                String url = ResponseCodeTracer.safeUrl(args[0]);
                OtaLog.i(SCOPE, "b.a gkaReq=2 url=" + url
                        + " i9=" + i9
                        + " conn=" + args[0].getClass().getName()
                        + " ctx=" + (args[1] == null ? "null" : args[1].getClass().getName()));
                OtaLog.trace(SCOPE, "b.a gkaReq=2 caller", 12);

                int[] depth = IN_GKA_REQUEST.get();
                if (depth == null) {
                    depth = new int[1];
                    IN_GKA_REQUEST.set(depth);
                }
                depth[0]++;
                GKA_CONN.set(args[0]);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "b.a logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                int[] depth = IN_GKA_REQUEST.get();
                if (depth == null) {
                    return;
                }
                if (--depth[0] <= 0) {
                    IN_GKA_REQUEST.remove();
                    GKA_CONN.remove();
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "b.a exit logging failed", t);
            }
        }
    }

    // ------------------------------------------------------------- (2) p5.b.t

    private static void hookTsJson(ClassLoader cl) {
        for (String fqcn : TracerConfig.TS_JSON_CLASSES) {
            Class<?> c;
            try {
                c = XposedHelpers.findClassIfExists(fqcn, cl);
            } catch (Throwable t) {
                c = null;
            }
            if (c == null) {
                OtaLog.i(SCOPE, "no /ts json class " + fqcn);
                continue;
            }
            OtaLog.i(SCOPE, "attach /ts json " + fqcn);
            for (String m : TracerConfig.TS_JSON_METHODS) {
                ClassHunter.hookAllByName(c, m, new TsJsonCallback(), SCOPE);
            }
        }
    }

    private static final class TsJsonCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, "ts json threw ex=" + OtaLog.describe(param.getThrowable()));
                    return;
                }
                Object r = param.getResult();
                if (r instanceof String) {
                    String s = (String) r;
                    String shown = s.length() > TracerConfig.MAX_BODY_CHARS
                            ? s.substring(0, TracerConfig.MAX_BODY_CHARS)
                            + "...(+" + (s.length() - TracerConfig.MAX_BODY_CHARS) + ")"
                            : s;
                    OtaLog.i(SCOPE, "ts json len=" + s.length()
                            + " sha256=" + OtaLog.digestFull(s));
                    OtaLog.i(SCOPE, "ts json=" + shown);
                } else {
                    OtaLog.i(SCOPE, "ts json return " + OtaLog.describe(r));
                }
                OtaLog.trace(SCOPE, "ts json caller", 10);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "ts json logging failed", t);
            }
        }
    }

    // ------------------------------------------ (3) addRequestProperty id/ts/ac/as

    private static void hookHeaders() {
        for (String cls : CONNECTION_CLASSES) {
            try {
                Class<?> c = XposedHelpers.findClass(cls, appCl);
                ClassHunter.hookAllByName(c, "addRequestProperty", new HeaderCallback(), SCOPE);
            } catch (Throwable t) {
                OtaLog.i(SCOPE, "addRequestProperty unavailable on " + cls
                        + " (" + t.getClass().getSimpleName() + ")");
            }
        }
    }

    private static final class HeaderCallback extends XC_MethodHook {

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Object[] args = param.args;
                if (args == null || args.length != 2) {
                    return;
                }
                if (!(args[0] instanceof String) || !(args[1] instanceof String)) {
                    return;
                }
                String key = (String) args[0];
                String value = (String) args[1];
                String lower = key.toLowerCase();

                boolean plain = contains(TracerConfig.HEADER_KEYS_PLAIN, lower);
                boolean hashed = contains(TracerConfig.HEADER_KEYS_HASHED, lower);
                if (!plain && !hashed) {
                    return;
                }
                // Two gates, both reusing existing module machinery:
                //  - the OTA call-stack filter
                //  - the OTA endpoint URL filter, or the very connection b.a(..2) got
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                Object conn = param.thisObject;
                String url = ResponseCodeTracer.safeUrl(conn);
                if (!isOtaEndpoint(url) && conn != GKA_CONN.get()) {
                    return;
                }
                if (hashed) {
                    // Signature material: length + SHA-256 only, never the value.
                    OtaLog.i(SCOPE, "header " + key + " len=" + value.length()
                            + " sha256=" + OtaLog.digestFull(value) + " url=" + url);
                } else {
                    OtaLog.i(SCOPE, "header " + key + "=" + value + " url=" + url);
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "header logging failed", t);
            }
        }
    }

    // --------------------------------- (4) /ts and (5) final download response

    private static void hookResponses() {
        for (String cls : CONNECTION_CLASSES) {
            try {
                Class<?> c = XposedHelpers.findClass(cls, appCl);
                ClassHunter.hookAllByName(c, "getResponseCode", new StatusCallback(), SCOPE);
                ClassHunter.hookAllByName(c, "getInputStream", new StreamCallback(), SCOPE);
                ClassHunter.hookAllByName(c, "getErrorStream", new StreamCallback(), SCOPE);
            } catch (Throwable t) {
                OtaLog.i(SCOPE, "response hooks unavailable on " + cls
                        + " (" + t.getClass().getSimpleName() + ")");
            }
        }
    }

    private static final class StatusCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                Object conn = param.thisObject;
                String url = ResponseCodeTracer.safeUrl(conn);
                if (!isOtaEndpoint(url)) {
                    return;
                }
                Object r = param.getResult();
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, kindOf(url) + " status threw ex="
                            + OtaLog.describe(param.getThrowable()) + " url=" + url);
                    return;
                }
                if (!(r instanceof Integer)) {
                    return;
                }
                int code = (Integer) r;
                OtaLog.i(SCOPE, kindOf(url) + " httpStatus=" + code + " url=" + url);
                OtaLog.trace(SCOPE, kindOf(url) + " request site", 12);

                if (isDownloadEndpoint(url)) {
                    DOWNLOAD_STATUS.set(code);
                    // "responseCode=2713" in the body is NOT this number. This is
                    // what the socket actually answered.
                    OtaLog.i(SCOPE, "download realHttpStatus=" + code + " url=" + url);
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "status logging failed", t);
            }
        }
    }

    private static final class StreamCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                Object conn = param.thisObject;
                String url = ResponseCodeTracer.safeUrl(conn);
                if (!isOtaEndpoint(url)) {
                    return;
                }
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, kindOf(url) + " stream threw ex="
                            + OtaLog.describe(param.getThrowable()) + " url=" + url);
                    return;
                }
                Object stream = param.getResult();

                // Which door the app actually used for the answer. Logged before
                // the null check on purpose: "getErrorStream returned null" is
                // itself the answer for a 2xx response.
                String via = param.method.getName();
                Integer st = DOWNLOAD_STATUS.get();
                String status = st == null ? "unknown" : String.valueOf(st);
                if (isDownloadEndpoint(url)) {
                    OtaLog.i(SCOPE, "download streamVia=" + via
                            + " realHttpStatus=" + status
                            + " stream=" + (stream == null
                            ? "null" : stream.getClass().getName())
                            + " url=" + url);
                } else {
                    OtaLog.i(SCOPE, kindOf(url) + " streamVia=" + via + " url=" + url);
                }

                if (stream == null) {
                    return;
                }
                // Start of a new OTA body on this thread: flush whatever came before.
                flushBody();
                TRACKED_STREAM.set(stream);
                TRACKED_URL.set(url);
                TRACKED_BODY.set(new ByteArrayOutputStream());
                ensureStreamHooked(stream.getClass());
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "stream logging failed", t);
            }
        }
    }

    /** Hook read/close on the concrete stream class, once per class. */
    private static void ensureStreamHooked(Class<?> streamClass) {
        if (!STREAM_CLASSES.add(streamClass.getName())) {
            return;
        }
        OtaLog.i(SCOPE, "body capture on " + streamClass.getName());
        ClassHunter.hookAllByName(streamClass, "read", new BodyReadCallback(), SCOPE);
        ClassHunter.hookAllByName(streamClass, "close", new BodyCloseCallback(), SCOPE);
    }

    /**
     * Observe only the bytes the app itself reads from the tracked OTA stream.
     * Nothing is consumed ahead of the app and the stream object is returned
     * untouched, so this cannot change what the app sees.
     */
    private static final class BodyReadCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.thisObject != TRACKED_STREAM.get()) {
                    return;
                }
                if (param.hasThrowable()) {
                    flushBody();
                    return;
                }
                Object r = param.getResult();
                if (!(r instanceof Integer)) {
                    return;
                }
                int n = (Integer) r;
                if (n < 0) {
                    flushBody();
                    return;
                }
                ByteArrayOutputStream bos = TRACKED_BODY.get();
                if (bos == null || bos.size() > TracerConfig.MAX_BODY_CHARS * 2) {
                    return;
                }
                Object[] args = param.args;
                if (args == null || args.length == 0) {
                    bos.write(n);
                } else if (args.length == 1 && args[0] instanceof byte[]) {
                    bos.write((byte[]) args[0], 0, n);
                } else if (args.length == 3 && args[0] instanceof byte[]
                        && args[1] instanceof Integer) {
                    bos.write((byte[]) args[0], (Integer) args[1], n);
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "body read logging failed", t);
            }
        }
    }

    private static final class BodyCloseCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.thisObject == TRACKED_STREAM.get()) {
                    flushBody();
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "body close logging failed", t);
            }
        }
    }

    private static void flushBody() {
        ByteArrayOutputStream bos = TRACKED_BODY.get();
        String url = TRACKED_URL.get();
        TRACKED_BODY.remove();
        TRACKED_STREAM.remove();
        TRACKED_URL.remove();
        if (bos == null || bos.size() == 0) {
            return;
        }
        String body = new String(bos.toByteArray(), StandardCharsets.UTF_8);
        if (body.length() > TracerConfig.MAX_BODY_CHARS) {
            body = body.substring(0, TracerConfig.MAX_BODY_CHARS)
                    + "...(+" + (body.length() - TracerConfig.MAX_BODY_CHARS) + ")";
        }
        OtaLog.i(SCOPE, kindOf(url) + " bodyBytes=" + bos.size() + " url=" + url);
        OtaLog.i(SCOPE, kindOf(url) + " body=" + body);
    }

    // ------------------------------------------------------------------ filters

    private static boolean contains(String[] keys, String lower) {
        for (String k : keys) {
            if (k.equals(lower)) {
                return true;
            }
        }
        return false;
    }

    /** Endpoint gate: only the OTA backend, never unrelated app traffic. */
    private static boolean isOtaEndpoint(String url) {
        if (url == null || url.length() == 0 || url.startsWith("url-unavailable")
                || "null".equals(url)) {
            return false;
        }
        String lower = url.toLowerCase();
        for (String hint : TracerConfig.DOWNLOAD_URL_HINTS) {
            if (lower.contains(hint)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The download endpoint only: OTA backend host AND a /download path.
     * safeUrl() keeps the path verbatim, so this matches the real URL.
     */
    private static boolean isDownloadEndpoint(String url) {
        if (url == null || url.length() == 0) {
            return false;
        }
        String lower = url.toLowerCase();
        boolean otaHost = false;
        for (String hint : TracerConfig.DOWNLOAD_URL_HINTS) {
            if (lower.contains(hint)) {
                otaHost = true;
                break;
            }
        }
        if (!otaHost) {
            return false;
        }
        for (String path : TracerConfig.DOWNLOAD_ENDPOINT_PATHS) {
            if (lower.contains(path)) {
                return true;
            }
        }
        return false;
    }

    private static String kindOf(String url) {
        if (url != null && url.toLowerCase().contains("/ts")) {
            return "ts";
        }
        return "download";
    }
}
