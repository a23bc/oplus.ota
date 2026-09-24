package com.a23bc.oplus.otatracer;

import java.security.Key;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Answers "is AndroidKeyStore / KeyStore involved, and where does the Key come from?".
 *
 * Hooks a few KeyStore entry points only, and only prints class / algorithm /
 * format / null-ness - never key material.
 */
public final class KeyStoreTracer {

    private static final String SCOPE = "KeyStore";

    private static final String[] CLASSES = {
            "java.security.KeyStore",
            "android.security.keystore.KeyStore",
    };

    private static boolean installed = false;

    private KeyStoreTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        hook(lpparam.classLoader, "java.security.KeyStore", "getInstance", String.class);
        hook(lpparam.classLoader, "java.security.KeyStore", "load",
                java.security.KeyStore.LoadStoreParameter.class);
        hook(lpparam.classLoader, "java.security.KeyStore", "getKey", String.class, char[].class);
        hook(lpparam.classLoader, "java.security.KeyStore", "getEntry", String.class,
                java.security.KeyStore.ProtectionParameter.class);
        hook(lpparam.classLoader, "java.security.KeyStore", "getCertificate", String.class);
        hook(lpparam.classLoader, "java.security.KeyPairGenerator", "getInstance", String.class);
        hook(lpparam.classLoader, "java.security.KeyFactory", "getInstance", String.class);
        hook(lpparam.classLoader, "java.security.Signature", "getInstance", String.class);
    }

    private static void hook(ClassLoader cl, String cls, String method, Class<?>... params) {
        try {
            Class<?> c = XposedHelpers.findClass(cls, cl);
            // findAndHookMethod takes (Class..., callback) flattened - build it explicitly.
            Object[] call = new Object[params.length + 1];
            System.arraycopy(params, 0, call, 0, params.length);
            call[params.length] = new KeyStoreCallback(cls, method);
            XposedHelpers.findAndHookMethod(c, method, call);
            OtaLog.i(SCOPE, "hooked " + cls + "#" + method);
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable " + cls + "#" + method
                    + " (" + t.getClass().getSimpleName() + ")");
        }
    }

    private static final class KeyStoreCallback extends XC_MethodHook {

        private final String cls;
        private final String method;

        KeyStoreCallback(String cls, String method) {
            this.cls = cls;
            this.method = method;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                Object[] args = param.args;
                StringBuilder sb = new StringBuilder();
                sb.append(method).append(" enter");
                if (args != null) {
                    for (int i = 0; i < args.length; i++) {
                        sb.append(" arg[").append(i).append("]=");
                        Object a = args[i];
                        if (a instanceof char[]) {
                            sb.append("char[").append(((char[]) a).length).append("]");
                        } else if (a instanceof String) {
                            sb.append("String(len=").append(((String) a).length()).append(")");
                        } else {
                            sb.append(OtaLog.describe(a));
                        }
                    }
                }
                OtaLog.i(SCOPE, sb.toString());
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "keystore before logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, method + " threw " + OtaLog.describe(param.getThrowable()));
                    return;
                }
                Object r = param.getResult();
                if (r instanceof Key) {
                    OtaLog.i(SCOPE, method + " result " + OtaLog.describeKey((Key) r));
                    OtaLog.trace(SCOPE, method + " result site", 10);
                } else {
                    OtaLog.i(SCOPE, method + " result " + OtaLog.describe(r));
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "keystore after logging failed", t);
            }
        }
    }
}
