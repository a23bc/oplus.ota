package com.a23bc.oplus.otatracer;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Traces DownloadException construction: mCode, mGKACode, message and cause.
 *
 * Hooked at the constructor only - the exception object is already fully built
 * when we read it, and nothing is modified.
 */
public final class DownloadExceptionTracer {

    private static final String SCOPE = "DownloadException";

    private static boolean installed = false;

    private DownloadExceptionTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            ClassHunter.watch("DownloadException",
                    TracerConfig.DOWNLOAD_EXCEPTION_CANDIDATES,
                    null,
                    new String[]{"downloadexception"},
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
        ClassHunter.hookAllConstructors(clazz, new CtorCallback(), SCOPE);
    }

    private static final class CtorCallback extends XC_MethodHook {
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Object thiz = param.thisObject;
                Object[] args = param.args;
                OtaLog.i(SCOPE, "created class=" + (thiz == null ? "null" : thiz.getClass().getName()));
                if (args != null) {
                    for (int i = 0; i < args.length; i++) {
                        OtaLog.i(SCOPE, "ctor arg[" + i + "] " + OtaLog.describe(args[i]));
                    }
                }
                if (thiz instanceof Throwable) {
                    Throwable t = (Throwable) thiz;
                    OtaLog.i(SCOPE, "msg=" + OtaLog.safeMsg(t.getMessage()));
                    Throwable cause = t.getCause();
                    OtaLog.i(SCOPE, "cause=" + (cause == null ? "null"
                            : cause.getClass().getName() + ": " + OtaLog.safeMsg(cause.getMessage())));
                }
                GetInfoThreadTracer.dumpCodeFields(SCOPE, "", thiz);
                OtaLog.trace(SCOPE, "created at", TracerConfig.STACK_DEPTH);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "ctor logging failed", t);
            }
        }
    }
}
