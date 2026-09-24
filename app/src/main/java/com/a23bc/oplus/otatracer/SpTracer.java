package com.a23bc.oplus.otatracer;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Question G: where does gakReqSpValue come from and who reads it.
 *
 * r19 also watches the internal-test (recruit) state, because that is what the
 * server keys the download on: is_recruit / recruitType come straight out of the
 * query response, and they are the only client-visible answer to
 * "does the server still think this device is recruited".
 *
 * Reads AND writes are echoed now - the values are written by the response
 * parser, so a write is the server's answer landing. Only keys matching a hint
 * are logged, and only for the OTA call stack. Strictly read-only.
 */
public final class SpTracer {

    private static final String SCOPE = "Prefs";

    private static final String SP_IMPL = "android.app.SharedPreferencesImpl";
    private static final String EDITOR_IMPL = "android.app.SharedPreferencesImpl$EditorImpl";

    private static boolean installed = false;

    private SpTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;

        hook(lpparam.classLoader, SP_IMPL, "getInt", String.class, int.class);
        hook(lpparam.classLoader, SP_IMPL, "getBoolean", String.class, boolean.class);
        hook(lpparam.classLoader, SP_IMPL, "getString", String.class, String.class);

        hook(lpparam.classLoader, EDITOR_IMPL, "putInt", String.class, int.class);
        hook(lpparam.classLoader, EDITOR_IMPL, "putBoolean", String.class, boolean.class);
        hook(lpparam.classLoader, EDITOR_IMPL, "putString", String.class, String.class);
        hook(lpparam.classLoader, EDITOR_IMPL, "remove", String.class);
    }

    private static void hook(ClassLoader cl, String cls, String method, Class<?>... params) {
        try {
            Class<?> c = XposedHelpers.findClass(cls, cl);
            Object[] call = new Object[params.length + 1];
            System.arraycopy(params, 0, call, 0, params.length);
            call[params.length] = new SpCallback();
            XposedHelpers.findAndHookMethod(c, method, call);
            OtaLog.i(SCOPE, "hooked " + cls + "#" + method);
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable " + cls + "#" + method
                    + " (" + t.getClass().getSimpleName() + ")");
        }
    }

    private static final class SpCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    return;
                }
                Object key = param.args != null && param.args.length > 0 ? param.args[0] : null;
                if (!(key instanceof String)) {
                    return;
                }
                // Cheap filter first: these are hot during startup, and building
                // a stack trace is not. Only interesting keys pay for it.
                String k = ((String) key).toLowerCase();
                if (!interesting(k)) {
                    return;
                }
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                String stored = param.args != null && param.args.length > 1
                        ? OtaLog.describe(param.args[1]) : "-";
                OtaLog.i(SCOPE, param.method.getName() + " key=" + key
                        + " value=" + stored + " result=" + OtaLog.describe(param.getResult()));
                OtaLog.trace(SCOPE, param.method.getName() + " site", 8);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "prefs logging failed", t);
            }
        }

        private boolean interesting(String lowerKey) {
            for (String hint : TracerConfig.SP_KEY_HINTS) {
                if (lowerKey.contains(hint)) {
                    return true;
                }
            }
            for (String hint : TracerConfig.RECRUIT_SP_KEYS) {
                if (lowerKey.contains(hint)) {
                    return true;
                }
            }
            return false;
        }
    }
}
