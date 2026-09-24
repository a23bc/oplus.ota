package com.a23bc.oplus.otatracer;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * r19: does the server still consider this device recruited?
 *
 * Three things, all read-only:
 *
 *  1. n5.h.D1(Context) - the gate itself:
 *         return !isEmpty(Settings.Global "recordOtaRecruitAid");
 *     Its value is printed live, so the answer is not inferred from a pref dump.
 *
 *  2. Settings.Global getString/putString for recordOtaRecruitAid. It is only
 *     written from oplus.intent.action.ACTION_OTA_RECRUIT_SUCCESS and cleared
 *     to null after a successful update, so watching it shows whether the server
 *     ever re-issued the recruit id.
 *
 *  3. The OTA component_update_url, purely so /ts and /update/v6 are recognisable.
 *
 * Nothing is written, no broadcast is faked, no value is invented. If the server
 * has dropped the record, this tracer will show an empty recruit id and D1=false -
 * which is the answer, not a problem to work around.
 */
public final class RecruitTracer {

    private static final String SCOPE = "Recruit";

    private static final String GLOBAL = "android.provider.Settings$Global";

    private static boolean installed = false;

    private RecruitTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;

        hookSettings(lpparam.classLoader, "getString",
                android.content.ContentResolver.class, String.class);
        hookSettings(lpparam.classLoader, "putString",
                android.content.ContentResolver.class, String.class, String.class);

        hookGate(lpparam.classLoader);
    }

    private static void hookSettings(ClassLoader cl, String method, Class<?>... params) {
        try {
            Class<?> c = XposedHelpers.findClass(GLOBAL, cl);
            Object[] call = new Object[params.length + 1];
            System.arraycopy(params, 0, call, 0, params.length);
            call[params.length] = new SettingsCallback();
            XposedHelpers.findAndHookMethod(c, method, call);
            OtaLog.i(SCOPE, "hooked Settings$Global#" + method);
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable Settings$Global#" + method
                    + " (" + t.getClass().getSimpleName() + ")");
        }
    }

    /** Key sits at index 1 for both getString and putString. */
    private static final class SettingsCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Object[] args = param.args;
                if (args == null || args.length < 2 || !(args[1] instanceof String)) {
                    return;
                }
                String key = (String) args[1];
                boolean hit = false;
                for (String want : TracerConfig.RECRUIT_SETTINGS_KEYS) {
                    if (want.equalsIgnoreCase(key)) {
                        hit = true;
                        break;
                    }
                }
                if (!hit) {
                    return;
                }
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                String value = args.length > 2 ? OtaLog.describe(args[2]) : "-";
                OtaLog.i(SCOPE, param.method.getName() + " key=" + key
                        + " value=" + value + " result=" + OtaLog.describe(param.getResult()));
                OtaLog.trace(SCOPE, param.method.getName() + " site", 8);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "settings logging failed", t);
            }
        }
    }

    private static void hookGate(ClassLoader cl) {
        Class<?> c;
        try {
            c = XposedHelpers.findClassIfExists(TracerConfig.RECRUIT_GATE_CLASS, cl);
        } catch (Throwable t) {
            c = null;
        }
        if (c == null) {
            OtaLog.i(SCOPE, "gate class not found: " + TracerConfig.RECRUIT_GATE_CLASS);
            return;
        }
        ClassHunter.hookAllByName(c, TracerConfig.RECRUIT_GATE_METHOD,
                new GateCallback(), SCOPE);
    }

    private static final class GateCallback extends XC_MethodHook {

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    return;
                }
                Object r = param.getResult();
                if (!(r instanceof Boolean)) {
                    return;
                }
                OtaLog.i(SCOPE, "D1 recruited=" + r + " caller=" + Thread.currentThread().getName());
                OtaLog.trace(SCOPE, "D1 site", 8);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "gate logging failed", t);
            }
        }
    }
}
