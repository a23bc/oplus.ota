package com.a23bc.oplus.otatracer;

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

    private AttestationTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
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
    }

    private static final class AttestCallback extends XC_MethodHook {

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
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
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, param.method.getName() + " threw");
                    OtaLog.stack(SCOPE, param.method.getName() + " exception:",
                            param.getThrowable());
                    return;
                }
                OtaLog.i(SCOPE, param.method.getName() + " return "
                        + OtaLog.describe(param.getResult()));
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "attest after logging failed", t);
            }
        }
    }
}
