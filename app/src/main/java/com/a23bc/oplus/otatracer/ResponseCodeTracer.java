package com.a23bc.oplus.otatracer;

import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Records HTTP response codes seen inside com.oplus.ota.
 *
 * Purpose: tell apart a server-originated 2304 from a code synthesised locally
 * after ecdsaSignPki() failed. Sequence numbers in the log give the ordering.
 *
 * Only a handful of well-known network entry points are hooked, and output is
 * suppressed unless the call stack belongs to the OTA app.
 */
public final class ResponseCodeTracer {

    private static final String SCOPE = "Response";

    private static final String[][] HOOKS = {
            {"com.android.okhttp.internal.huc.HttpURLConnectionImpl", "getResponseCode"},
            {"com.android.okhttp.internal.huc.HttpURLConnectionImpl", "getInputStream"},
            {"java.net.HttpURLConnection", "getResponseCode"},
            {"okhttp3.Response", "code"},
            {"okhttp3.internal.http.RealResponseBody", "source"},
            {"com.android.volley.toolbox.HttpStack", "performRequest"},
    };

    private static boolean installed = false;

    private ResponseCodeTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        for (String[] pair : HOOKS) {
            hook(lpparam.classLoader, pair[0], pair[1]);
        }
    }

    private static void hook(ClassLoader cl, String cls, String method) {
        try {
            Class<?> c = XposedHelpers.findClass(cls, cl);
            XposedHelpers.findAndHookMethod(c, method, new CodeCallback(cls, method));
            OtaLog.i(SCOPE, "hooked " + cls + "#" + method);
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable " + cls + "#" + method
                    + " (" + t.getClass().getSimpleName() + ")");
        }
    }

    private static final class CodeCallback extends XC_MethodHook {

        private final String cls;
        private final String method;

        CodeCallback(String cls, String method) {
            this.cls = cls;
            this.method = method;
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                Object thiz = param.thisObject;
                String url = safeUrl(thiz);
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, method + " threw " + OtaLog.describe(param.getThrowable())
                            + " url=" + url);
                    return;
                }
                Object r = param.getResult();
                if (r instanceof Integer) {
                    int code = (Integer) r;
                    OtaLog.i(SCOPE, "responseCode=" + code + " url=" + url);
                    if (code == 2304) {
                        OtaLog.i(SCOPE, "2304 observed - compare seq with [SignVerify] ecdsaSignPki");
                        OtaLog.trace(SCOPE, "2304 site", TracerConfig.STACK_DEPTH);
                    }
                } else {
                    OtaLog.i(SCOPE, method + " return " + OtaLog.describe(r) + " url=" + url);
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "response logging failed", t);
            }
        }

    /**
     * scheme://host/path plus query *names* only - values may be tokens.
     * Package-visible so other tracers reuse the same sanitising rule instead
     * of inventing a second one.
     */
    static String safeUrl(Object thiz) {
        if (thiz == null) {
            return "null";
        }
        try {
            Method m = thiz.getClass().getMethod("getURL");
            Object u = m.invoke(thiz);
            if (u == null) {
                return "null";
            }
            String s = String.valueOf(u);
            int q = s.indexOf('?');
            if (q < 0) {
                return s;
            }
            String base = s.substring(0, q);
            StringBuilder names = new StringBuilder();
            for (String pair : s.substring(q + 1).split("&")) {
                int eq = pair.indexOf('=');
                if (names.length() > 0) {
                    names.append(',');
                }
                names.append(eq < 0 ? pair : pair.substring(0, eq));
            }
            return base + "?keys=[" + names + "]";
        } catch (Throwable t) {
            return "url-unavailable(" + thiz.getClass().getSimpleName() + ")";
        }
    }
}
