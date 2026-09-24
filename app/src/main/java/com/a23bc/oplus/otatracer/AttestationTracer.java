package com.a23bc.oplus.otatracer;

import android.os.Handler;
import android.os.Looper;

import java.lang.reflect.Method;
import java.util.List;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Watches the PKI SDK's AttestationUtil.
 *
 * It showed up in the getKey() stack as deleteKeyIfExists / createApplicationPublicKey,
 * i.e. it is the component that is supposed to own the attestation key pair. It is not
 * obfuscated, so every declared method can be observed directly, read-only.
 *
 * Goal: see whether it tries to create the key, what parameters it uses, and whether it
 * swallows an exception - that would explain why no attestation key ever existed.
 */
public final class AttestationTracer {

    private static final String SCOPE = "Attest";

    private static boolean installed = false;

    /**
     * True while the SDK is inside its own generateX509 path. The repair must
     * yield then: AttestationManager is about to create the attestation key
     * itself, and a plain EC key created first would take the alias and leave
     * the certificate without an attestation extension.
     */
    private static final java.util.concurrent.atomic.AtomicInteger GENERATE_DEPTH =
            new java.util.concurrent.atomic.AtomicInteger();

    private AttestationTracer() {
    }

    public static boolean isSdkGenerating() {
        return GENERATE_DEPTH.get() > 0;
    }

    private static volatile ClassLoader appCl;

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        appCl = lpparam.classLoader;
        for (String fqcn : TracerConfig.ATTESTATION_CLASSES) {
            Class<?> c;
            try {
                c = XposedHelpers.findClassIfExists(fqcn, lpparam.classLoader);
            } catch (Throwable t) {
                c = null;
            }
            if (c == null) {
                OtaLog.i(SCOPE, "no class " + fqcn);
                continue;
            }
            OtaLog.i(SCOPE, "attach " + fqcn);
            ClassHunter.hookAllDeclaredMethods(c, new AttestCallback(), SCOPE,
                    TracerConfig.MAX_METHODS_PER_CLASS);
        }

        dumpCmdTypes();
        scheduleCryptoEngScan();
    }

    /**
     * The HIDL service logs "have no permission calling cmd:10009" - find out
     * which command that is by dumping the SDK's own command enum.
     */
    private static void dumpCmdTypes() {
        for (String fqcn : TracerConfig.CRYPTO_CMD_TYPE_CLASSES) {
            try {
                Class<?> c = Class.forName(fqcn, false, appCl);
                Object[] constants = c.getEnumConstants();
                if (constants == null) {
                    OtaLog.i(SCOPE, "cmd type " + fqcn + " is not an enum");
                    continue;
                }
                StringBuilder sb = new StringBuilder("cmdTypes ");
                for (Object o : constants) {
                    Integer code = readIntCode(o);
                    if (sb.length() > 0) {
                        sb.append(' ');
                    }
                    sb.append(o).append('=').append(code == null ? "?" : code);
                }
                OtaLog.i(SCOPE, sb.toString());
            } catch (Throwable t) {
                OtaLog.i(SCOPE, "no cmd type " + fqcn + " (" + t.getClass().getSimpleName() + ")");
            }
        }
    }

    /** Read an int code off an enum constant: try the usual getters, then fields. */
    private static Integer readIntCode(Object constant) {
        for (String getter : new String[]{"getCode", "getValue", "getCmd", "getIntValue"}) {
            try {
                Method m = constant.getClass().getMethod(getter);
                Object v = m.invoke(constant);
                if (v instanceof Integer) {
                    return (Integer) v;
                }
            } catch (Throwable ignored) {
                // Try the next one.
            }
        }
        for (java.lang.reflect.Field f : constant.getClass().getDeclaredFields()) {
            if (f.getType() == int.class && !f.isSynthetic()) {
                try {
                    f.setAccessible(true);
                    return (Integer) f.get(constant);
                } catch (Throwable ignored) {
                    // Try the next one.
                }
            }
        }
        return null;
    }

    /**
     * The CryptoEng client class name is unknown, so find it by keyword in the
     * background and hook it - that is where "Cryptoeng Service return fail"
     * originates.
     */
    private static void scheduleCryptoEngScan() {
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            for (String keyword : TracerConfig.CRYPTO_ENG_KEYWORDS) {
                                List<Class<?>> found = ClassHunter.findByKeyword(keyword,
                                        TracerConfig.CRYPTO_ENG_MAX_CLASSES);
                                for (Class<?> c : found) {
                                    OtaLog.i(SCOPE, "cryptoeng candidate " + c.getName());
                                    ClassHunter.hookAllDeclaredMethods(c, new AttestCallback(),
                                            SCOPE, TracerConfig.CRYPTO_ENG_MAX_METHODS);
                                }
                            }
                        } catch (Throwable t) {
                            OtaLog.err(SCOPE, "cryptoeng scan failed", t);
                        }
                    }
                }, "OtaTracer-cryptoeng").start();
            }
        }, TracerConfig.CRYPTO_ENG_SCAN_DELAY_MS);
    }

    private static boolean isVoid(java.lang.reflect.Member m) {
        return m instanceof Method && ((Method) m).getReturnType() == void.class;
    }

    private static final class AttestCallback extends XC_MethodHook {

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.method.getName().startsWith("generate")) {
                    GENERATE_DEPTH.incrementAndGet();
                }
                StringBuilder sb = new StringBuilder(param.method.getName()).append(" enter");
                Object[] args = param.args;
                if (args != null) {
                    for (int i = 0; i < args.length; i++) {
                        sb.append(" arg[").append(i).append("]=").append(OtaLog.describe(args[i]));
                    }
                }
                OtaLog.i(SCOPE, sb.toString());
                OtaLog.trace(SCOPE, param.method.getName() + " caller", 12);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "attest before logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.method.getName().startsWith("generate")) {
                    GENERATE_DEPTH.decrementAndGet();
                }
                if (param.hasThrowable()) {
                    Throwable th = param.getThrowable();
                    OtaLog.i(SCOPE, param.method.getName() + " threw ex=" + (th == null
                            ? "null"
                            : th.getClass().getName() + ": " + OtaLog.safeMsg(th.getMessage())));
                    OtaLog.stack(SCOPE, param.method.getName() + " exception:",
                            param.getThrowable());
                    return;
                }
                // r14: generate() / generateX509() must be readable as
                // "did it produce an object at all", so type and null-ness are
                // spelled out instead of being left inside describe().
                Object r = param.getResult();
                StringBuilder sb = new StringBuilder(param.method.getName())
                        .append(" return ").append(OtaLog.describe(r));
                if (isVoid(param.method)) {
                    sb.append(" void=true");
                } else {
                    sb.append(" type=").append(r == null ? "null" : r.getClass().getName())
                            .append(" isNull=").append(r == null);
                }
                OtaLog.i(SCOPE, sb.toString());
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "attest after logging failed", t);
            }
        }
    }
}
