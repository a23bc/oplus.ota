package com.a23bc.oplus.otatracer;

import android.util.Log;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Echoes the app's own log lines that matter ("download denied", error codes, ...).
 *
 * Single-method hooks with a strict keyword filter, so the volume stays small and
 * unrelated chatter is dropped. Our own output is excluded via OtaLog.SELF_LOG.
 */
public final class LogTracer {

    private static final String SCOPE = "AppLog";

    private static boolean installed = false;

    private LogTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        hook(lpparam.classLoader, "d", String.class, String.class);
        hook(lpparam.classLoader, "i", String.class, String.class);
        hook(lpparam.classLoader, "w", String.class, String.class);
        hook(lpparam.classLoader, "e", String.class, String.class);
        hook(lpparam.classLoader, "v", String.class, String.class);
    }

    private static void hook(ClassLoader cl, String method, Class<?>... params) {
        try {
            // Log is a boot class: pass the Class object directly instead of
            // asking a (possibly already busy) app class loader to resolve it.
            XposedHelpers.findAndHookMethod(Log.class, method, params, new LogCallback(method));
            OtaLog.i(SCOPE, "hooked android.util.Log#" + method);
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable Log#" + method
                    + " (" + t.getClass().getSimpleName() + ")");
        }
    }

    /** Sliding one-second budget for echoed lines (no lock, approximate is fine). */
    private static final java.util.concurrent.atomic.AtomicInteger ECHOED =
            new java.util.concurrent.atomic.AtomicInteger(0);
    private static volatile long windowStart = 0L;

    private static boolean allowMore() {
        long now = System.currentTimeMillis();
        if (now - windowStart > 1000L) {
            windowStart = now;
            ECHOED.set(0);
        }
        return ECHOED.incrementAndGet() <= TracerConfig.LOG_ECHO_MAX_PER_SEC;
    }

    private static final class LogCallback extends XC_MethodHook {

        private final String method;

        LogCallback(String method) {
            this.method = method;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Boolean self = OtaLog.SELF_LOG.get();
                if (self != null && self) {
                    return;
                }
                Object[] args = param.args;
                if (args == null || args.length < 2) {
                    return;
                }
                Object tagObj = args[0];
                Object msgObj = args[1];
                if (!(tagObj instanceof String)) {
                    return;
                }
                String tag = (String) tagObj;
                if (OtaLog.TAG.equals(tag)) {
                    return; // our own line
                }
                String msg = msgObj == null ? "null" : String.valueOf(msgObj);
                String lowTag = tag.toLowerCase();
                String lowMsg = msg.toLowerCase();

                boolean tagHit = false;
                for (String hint : TracerConfig.LOG_TAG_HINTS) {
                    if (lowTag.contains(hint)) {
                        tagHit = true;
                        break;
                    }
                }
                boolean msgHit = false;
                for (String hint : TracerConfig.LOG_MSG_HINTS) {
                    if (lowMsg.contains(hint)) {
                        msgHit = true;
                        break;
                    }
                }
                if (!tagHit && !msgHit) {
                    return;
                }
                if (!allowMore()) {
                    return; // Log is hot; never flood logcat or the tracer.
                }
                OtaLog.i(SCOPE, method + " tag=" + tag + " msg=" + OtaLog.safeMsg(msg));
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "log tracer failed", t);
            }
        }
    }
}
