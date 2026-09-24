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
        hook(java.security.KeyStore.class, "getInstance", String.class);
        hook(java.security.KeyStore.class, "load", java.security.KeyStore.LoadStoreParameter.class);
        hook(java.security.KeyStore.class, "getKey", String.class, char[].class);
        hook(java.security.KeyStore.class, "getEntry", String.class,
                java.security.KeyStore.ProtectionParameter.class);
        hook(java.security.KeyStore.class, "getCertificate", String.class);
        hook(java.security.KeyPairGenerator.class, "getInstance", String.class);
        hook(java.security.KeyFactory.class, "getInstance", String.class);
        hook(java.security.Signature.class, "getInstance", String.class);
    }

    /** Boot classes are passed as Class objects: no class-loader lookup needed. */
    private static void hook(Class<?> c, String method, Class<?>... params) {
        try {
            // findAndHookMethod takes (Class..., callback) flattened - build it explicitly.
            Object[] call = new Object[params.length + 1];
            System.arraycopy(params, 0, call, 0, params.length);
            call[params.length] = new KeyStoreCallback(c.getName(), method);
            XposedHelpers.findAndHookMethod(c, method, call);
            OtaLog.i(SCOPE, "hooked " + c.getName() + "#" + method);
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable " + c.getName() + "#" + method
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
