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

        // Fallback that does not depend on any class name: whatever the signing
        // helper is called, it ends up in Signature.initSign(key). Note that
        // getInstance() hands out Signature$Delegate, which overrides these
        // methods - so both the base class and the delegate must be hooked.
        hookSignature("java.security.Signature", "initSign", java.security.PrivateKey.class);
        hookSignature("java.security.Signature$Delegate", "initSign", java.security.PrivateKey.class);
        hookSignature("java.security.Signature", "sign");
        hookSignature("java.security.Signature$Delegate", "sign");

        // Why is ota_pki_attest missing? Watch every place a key could be created
        // or imported. The r4 trace showed no KeyPairGenerator.getInstance call at
        // all, so "was it ever generated" is the open question.
        hook(java.security.KeyPairGenerator.class, "generateKeyPair");
        hook(java.security.KeyPairGenerator.class, "initialize",
                java.security.spec.AlgorithmParameterSpec.class, java.security.SecureRandom.class);
        hook(java.security.KeyPairGenerator.class, "initialize", int.class,
                java.security.SecureRandom.class);
        hook(javax.crypto.KeyGenerator.class, "generateKey");
        hook(java.security.KeyStore.class, "setEntry", String.class,
                java.security.KeyStore.Entry.class,
                java.security.KeyStore.ProtectionParameter.class);
        hook(java.security.KeyStore.class, "setKeyEntry", String.class, Key.class,
                char[].class, java.security.cert.Certificate[].class);
        hook(java.security.KeyStore.class, "deleteEntry", String.class);
        hook(java.security.KeyStore.class, "containsAlias", String.class);
    }

    private static void hookSignature(String cls, String method, Class<?>... params) {
        try {
            Class<?> c = Class.forName(cls);
            Object[] call = new Object[params.length + 1];
            System.arraycopy(params, 0, call, 0, params.length);
            call[params.length] = new SignCallback(method);
            XposedHelpers.findAndHookMethod(c, method, call);
            OtaLog.i(SCOPE, "hooked " + cls + "#" + method);
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable " + cls + "#" + method
                    + " (" + t.getClass().getSimpleName() + ")");
        }
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

    /** Signature.initSign / sign: shows the Key actually handed to the signer. */
    private static final class SignCallback extends XC_MethodHook {

        private final String method;

        SignCallback(String method) {
            this.method = method;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                StringBuilder sb = new StringBuilder(method).append(" enter");
                Object[] args = param.args;
                if (args != null) {
                    for (int i = 0; i < args.length; i++) {
                        sb.append(" arg[").append(i).append("]=").append(OtaLog.describe(args[i]));
                    }
                }
                OtaLog.i(SCOPE, sb.toString());
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "signature before logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (!OtaLog.callerIsTargetApp()) {
                    return;
                }
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, method + " threw");
                    OtaLog.stack(SCOPE, method + " exception:", param.getThrowable());
                    return;
                }
                // Never print signature bytes - describe() reports length only.
                OtaLog.i(SCOPE, method + " result " + OtaLog.describe(param.getResult()));
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "signature after logging failed", t);
            }
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
                            // Alias / KeyStore type: an identifier, not key material.
                            // Passwords stay unprinted (char[] above).
                            sb.append("\"").append(OtaLog.safeMsg((String) a)).append("\"");
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
