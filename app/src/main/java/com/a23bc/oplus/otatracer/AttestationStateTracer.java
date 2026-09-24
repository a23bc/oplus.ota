package com.a23bc.oplus.otatracer;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * r20: what does this device's own attestation actually claim?
 *
 * android.boot.* properties can be rewritten by a hiding module. The attestation
 * cannot: KeyMint builds it in the TEE from the state the bootloader handed over,
 * so isOemLock / rootState / deviceSecurityLevel report the real thing. Those
 * fields ride in the "ac" header, and are the only device-integrity evidence the
 * server gets.
 *
 * This dumps the parsed values via the SDK's own parser. Pure observation:
 * nothing is regenerated, rewritten or spoofed - if the device is unlocked, this
 * says so, which is the point.
 *
 * Reading the numbers:
 *   oemLockState = -1, rootState = -1   -> id attestation never got built
 *                                          (matches packIdAttestation()==false and
 *                                           the cryptoeng permission failures)
 *   oemLockState = 0                    -> hardware reports bootloader unlocked
 *   oemLockState = 1, rootState = 0     -> hardware reports locked + VERIFIED,
 *                                          so the refusal is not about boot state
 */
public final class AttestationStateTracer {

    private static final String SCOPE = "AttestState";

    private static final String RECORD =
            "com.allawn.cryptography.security.attestation.ParsedAttestationRecord";

    private static final String[] GETTERS = {
            "getOemLockState", "getRootState", "getDeviceSecurityLevel",
            "getAttestationSecurityLevel", "getExpireDays",
            "getAttestationIdModel", "getAttestationIdDevice",
            "getAttestationIdBrand", "getAttestationIdManufacturer",
    };

    private static boolean installed = false;

    private AttestationStateTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;

        Class<?> c;
        try {
            c = XposedHelpers.findClassIfExists(RECORD, lpparam.classLoader);
        } catch (Throwable t) {
            c = null;
        }
        if (c == null) {
            OtaLog.i(SCOPE, "no class " + RECORD);
            return;
        }
        OtaLog.i(SCOPE, "attach " + RECORD);

        ClassHunter.hookAllConstructors(c, new RecordCallback("<init>"), SCOPE);
        for (String m : GETTERS) {
            ClassHunter.hookAllByName(c, m, new RecordCallback(m), SCOPE);
        }
    }

    private static final class RecordCallback extends XC_MethodHook {

        private final String name;

        RecordCallback(String name) {
            this.name = name;
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    return;
                }
                if ("<init>".equals(name)) {
                    Object[] args = param.args;
                    OtaLog.i(SCOPE, "ParsedAttestationRecord created argTypes="
                            + (args == null ? "none" : describeArgs(args)));
                    return;
                }
                Object r = param.getResult();
                // -1 is the "field absent" default, so it is worth spelling out.
                String note = "";
                if (r instanceof Integer && ((Integer) r).intValue() == -1) {
                    note = " (absent - id attestation missing?)";
                }
                if (r instanceof String && ((String) r).length() == 0) {
                    note = " (empty)";
                }
                OtaLog.i(SCOPE, name + " = " + OtaLog.describe(r) + note);
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "attestation state logging failed", t);
            }
        }

        private String describeArgs(Object[] args) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < args.length; i++) {
                if (i > 0) {
                    sb.append(',');
                }
                sb.append(args[i] == null ? "null" : args[i].getClass().getSimpleName());
            }
            return sb.toString();
        }
    }
}
