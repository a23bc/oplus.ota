package com.a23bc.oplus.otatracer;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Traces GetInfoThread: where the download request starts, what comes back,
 * and where "download denied" / exceptions surface.
 *
 * Only named/obvious methods of this one class are hooked - no package-wide hooks.
 */
public final class GetInfoThreadTracer {

    private static final String SCOPE = "GetInfoThread";

    private static boolean installed = false;

    private GetInfoThreadTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            ClassHunter.watch("GetInfoThread",
                    TracerConfig.GET_INFO_THREAD_CANDIDATES,
                    null,
                    new String[]{"getinfothread"},
                    new ClassHunter.ClassVisitor() {
                        @Override
                        public void onClass(Class<?> clazz) {
                            attach(clazz);
                        }
                    });
        } catch (Throwable t) {
            OtaLog.err(SCOPE, "watch registration failed", t);
        }
    }

    private static void attach(Class<?> clazz) {
        OtaLog.i(SCOPE, "attach class=" + clazz.getName());

        // The thread body: log entry, exit and anything thrown out of it.
        ClassHunter.hookAllByName(clazz, "run", new RunCallback(), SCOPE);

        // Selected methods that plausibly build or dispatch the request.
        Method[] methods;
        try {
            methods = clazz.getDeclaredMethods();
        } catch (Throwable t) {
            OtaLog.err(SCOPE, "getDeclaredMethods failed", t);
            return;
        }
        int hooked = 0;
        for (Method m : methods) {
            if (hooked >= TracerConfig.MAX_METHODS_PER_CLASS) {
                OtaLog.i(SCOPE, "method cap reached (" + TracerConfig.MAX_METHODS_PER_CLASS + ")");
                break;
            }
            String lower = m.getName().toLowerCase();
            boolean hit = false;
            for (String hint : TracerConfig.GET_INFO_METHOD_HINTS) {
                if (lower.contains(hint.toLowerCase())) {
                    hit = true;
                    break;
                }
            }
            if (!hit || "run".equals(m.getName())) {
                continue;
            }
            ClassHunter.hookAllByName(clazz, m.getName(), new RequestCallback(m.getName()), SCOPE);
            hooked++;
        }
        OtaLog.i(SCOPE, "extra methods hooked=" + hooked);
    }

    private static final class RunCallback extends XC_MethodHook {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                OtaLog.i(SCOPE, "run enter thread=" + Thread.currentThread().getName());
            } catch (Throwable ignored) {
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, "run threw");
                    OtaLog.stack(SCOPE, "run exception:", param.getThrowable());
                    return;
                }
                OtaLog.i(SCOPE, "run exit");
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "run logging failed", t);
            }
        }
    }

    /** Request-ish methods: dump safe integer/string state, never bodies. */
    private static final class RequestCallback extends XC_MethodHook {

        private final String method;

        RequestCallback(String method) {
            this.method = method;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                OtaLog.i(SCOPE, method + " enter");
                Object[] args = param.args;
                if (args != null) {
                    for (int i = 0; i < args.length; i++) {
                        OtaLog.i(SCOPE, method + " arg[" + i + "] " + OtaLog.describe(args[i]));
                    }
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "before logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    Throwable th = param.getThrowable();
                    OtaLog.i(SCOPE, method + " threw " + th.getClass().getName());
                    // DownloadException carries mCode / mGKACode: surface them here too.
                    dumpCodeFields(SCOPE, method + " exception ", th);
                    OtaLog.stack(SCOPE, method + " exception:", th);
                    return;
                }
                Object r = param.getResult();
                OtaLog.i(SCOPE, method + " return " + OtaLog.describe(r));
                if (r != null && r.getClass().getName().toLowerCase().contains("response")) {
                    dumpCodeFields(SCOPE, method + " response ", r);
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "after logging failed", t);
            }
        }
    }

    /** Reflectively read int/long/String "code"-like fields; read-only. */
    static void dumpCodeFields(String scope, String label, Object obj) {
        if (obj == null) {
            return;
        }
        Class<?> c = obj.getClass();
        while (c != null && c != Object.class) {
            Field[] fs;
            try {
                fs = c.getDeclaredFields();
            } catch (Throwable t) {
                return;
            }
            for (Field f : fs) {
                String fn = f.getName().toLowerCase();
                if (!(fn.contains("code") || fn.contains("msg") || fn.contains("status"))) {
                    continue;
                }
                try {
                    f.setAccessible(true);
                    Object v = f.get(obj);
                    Class<?> ft = f.getType();
                    if (ft == int.class || ft == Integer.class
                            || ft == long.class || ft == Long.class) {
                        OtaLog.i(scope, label + f.getName() + "=" + v);
                    } else if (ft == boolean.class || ft == Boolean.class) {
                        OtaLog.i(scope, label + f.getName() + "=" + v);
                    } else if (ft == String.class) {
                        OtaLog.i(scope, label + f.getName() + " " + OtaLog.describe(v));
                    }
                } catch (Throwable ignored) {
                    // Field not readable on this ROM; skip silently.
                }
            }
            c = c.getSuperclass();
        }
    }
}
