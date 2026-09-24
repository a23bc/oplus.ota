package com.a23bc.oplus.otatracer;

import java.security.Key;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Traces SignVerifyUtils.
 *
 * Focus: what Key object actually reaches ecdsaSignPki(), whether it is null,
 * what provider/format it claims, and whether the failure happens before the
 * network request goes out.
 *
 * Read-only: no argument, return value or throwable is ever rewritten.
 */
public final class SignVerifyTracer {

    private static final String SCOPE = "SignVerify";

    private static boolean installed = false;

    private SignVerifyTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;

        // Classes identified from the r4 stack trace. Their method names are
        // obfuscated (ecdsaSignPki -> b.d()), so hook everything they declare.
        for (String fqcn : TracerConfig.SIGN_VERIFY_EXACT_CLASSES) {
            Class<?> c = null;
            try {
                c = XposedHelpers.findClassIfExists(fqcn, lpparam.classLoader);
            } catch (Throwable t) {
                c = null;
            }
            if (c != null) {
                attachAll(c);
            } else {
                OtaLog.i(SCOPE, "no exact class " + fqcn);
            }
        }

        try {
            ClassHunter.watch("SignVerifyUtils",
                    TracerConfig.SIGN_VERIFY_CLASS_CANDIDATES,
                    new String[]{"ecdsaSignPki", "getGkaReqDownloadType"},
                    new String[]{"signverify"},
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

    /** Attach to the interesting methods of a resolved SignVerify-like class. */
    private static void attach(Class<?> clazz) {
        OtaLog.i(SCOPE, "attach class=" + clazz.getName());

        int hooked = 0;
        for (String method : TracerConfig.SIGN_VERIFY_METHODS) {
            if ("ecdsaSignPki".equals(method) || "ecdsaSign".equals(method)
                    || "signPki".equals(method)) {
                hooked += ClassHunter.hookAllByName(clazz, method, new SignCallback(method), SCOPE);
            } else {
                hooked += ClassHunter.hookAllByName(clazz, method, new TypeCallback(method), SCOPE);
            }
        }
        if (hooked > 0) {
            ClassHunter.markSatisfied("SignVerifyUtils");
        } else {
            OtaLog.i(SCOPE, "no target method on " + clazz.getName()
                    + " - keeping the deep scan armed");
        }
    }

    /** Every declared method, for obfuscated SignVerify classes. */
    private static void attachAll(Class<?> clazz) {
        OtaLog.i(SCOPE, "attach-all class=" + clazz.getName());
        int hooked = ClassHunter.hookAllDeclaredMethods(clazz, new AnyMethodCallback(),
                SCOPE, TracerConfig.MAX_METHODS_PER_CLASS);
        if (hooked > 0) {
            ClassHunter.markSatisfied("SignVerifyUtils");
        }
    }

    /**
     * Generic observer for a class whose method names are meaningless: prints
     * arguments, return value and any exception, without touching any of them.
     */
    private static final class AnyMethodCallback extends XC_MethodHook {

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                StringBuilder sb = new StringBuilder()
                        .append(param.method.getName()).append(" enter");
                Object[] args = param.args;
                if (args != null) {
                    for (int i = 0; i < args.length; i++) {
                        sb.append(" arg[").append(i).append("]=").append(OtaLog.describe(args[i]));
                    }
                }
                OtaLog.i(SCOPE, sb.toString());
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "method enter logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, param.method.getName() + " threw");
                    OtaLog.stack(SCOPE, param.method.getName() + " exception:",
                            param.getThrowable());
                    return;
                }
                OtaLog.i(SCOPE, param.method.getName() + " return "
                        + OtaLog.describe(param.getResult()));
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "method exit logging failed", t);
            }
        }
    }

    // ------------------------------------------------------------- ecdsaSignPki

    private static final class SignCallback extends XC_MethodHook {

        private final String method;
        private final ThreadLocal<Long> start = new ThreadLocal<>();

        SignCallback(String method) {
            this.method = method;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                start.set(System.nanoTime());
                OtaLog.i(SCOPE, method + " enter");
                Object[] args = param.args;
                int n = args == null ? 0 : args.length;
                OtaLog.i(SCOPE, method + " argCount=" + n);
                boolean sawKey = false;
                for (int i = 0; i < n; i++) {
                    Object a = args[i];
                    OtaLog.i(SCOPE, method + " arg[" + i + "] type="
                            + (a == null ? "null" : a.getClass().getName()));
                    if (a instanceof Key) {
                        sawKey = true;
                        OtaLog.i(SCOPE, "key index=" + i + " " + OtaLog.describeKey((Key) a));
                    } else if (a != null) {
                        OtaLog.i(SCOPE, method + " arg[" + i + "] " + OtaLog.describe(a));
                    }
                }
                if (!sawKey) {
                    OtaLog.i(SCOPE, "key null=n/a(no java.security.Key argument present)");
                }
                OtaLog.trace(SCOPE, method + " caller", TracerConfig.STACK_DEPTH);
            } catch (Throwable t) {
                // Swallowed on purpose: a tracer must never break the OTA flow.
                OtaLog.err(SCOPE, "before logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Long t0 = start.get();
                long ms = t0 == null ? -1 : (System.nanoTime() - t0) / 1000000L;
                if (param.hasThrowable()) {
                    Throwable th = param.getThrowable();
                    OtaLog.i(SCOPE, method + " threw");
                    OtaLog.stack(SCOPE, method + " exception:", th);
                    OtaLog.i(SCOPE, method + " result=THROW(before network send="
                            + "check seq order against [GetInfoThread] request)");
                    return;
                }
                Object r = param.getResult();
                OtaLog.i(SCOPE, method + " return " + OtaLog.describe(r));
                OtaLog.i(SCOPE, method + " duration=" + ms + "ms");
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "after logging failed", t);
            }
        }
    }

    // -------------------------------------------------- getGkaReqDownloadType

    private static final class TypeCallback extends XC_MethodHook {

        private final String method;

        TypeCallback(String method) {
            this.method = method;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                OtaLog.i(SCOPE, method + " enter");
            } catch (Throwable ignored) {
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    OtaLog.stack(SCOPE, method + " exception:", param.getThrowable());
                    return;
                }
                Object r = param.getResult();
                OtaLog.i(SCOPE, method + " return " + OtaLog.describe(r));
                // Question G: which code path consumes gakReqSpValue.
                OtaLog.trace(SCOPE, method + " caller", TracerConfig.STACK_DEPTH);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "after logging failed", t);
            }
        }
    }
}
