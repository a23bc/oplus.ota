package com.a23bc.oplus.otatracer;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Question G: where does gakReqSpValue come from and who reads it.
 *
 * Only int reads are echoed (no strings, no tokens), and only for keys whose name
 * looks related to gka / download type / signing.
 */
public final class SpTracer {

    private static final String SCOPE = "Prefs";

    private static boolean installed = false;

    private SpTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        hook(lpparam.classLoader, "android.app.SharedPreferencesImpl", "getInt",
                String.class, int.class);
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
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                if (param.hasThrowable()) {
                    return;
                }
                Object key = param.args != null && param.args.length > 0 ? param.args[0] : null;
                if (!(key instanceof String)) {
                    return;
                }
                String k = ((String) key).toLowerCase();
                boolean hit = false;
                for (String hint : TracerConfig.SP_KEY_HINTS) {
                    if (k.contains(hint)) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) {
                    return;
                }
                OtaLog.i(SCOPE, "getInt key=" + key + " value=" + param.getResult());
                OtaLog.trace(SCOPE, "getInt site", 8);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "prefs logging failed", t);
            }
        }
    }
}
