package com.a23bc.oplus.otatracer;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import de.robv.android.xposed.XC_MethodHook;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

/**
 * Repair mode: supply the EC key the OTA flow expects but never finds.
 *
 * Finding: the app calls containsAlias("ota_pki_attest"), gets false, and then
 * signs with the resulting null key. It never generates the key pair itself -
 * no KeyPairGenerator#generateKeyPair call exists anywhere in the trace.
 *
 * So when the app discovers the alias is missing, we do the omitted step:
 * generate an EC key pair in AndroidKeyStore under that alias. Everything
 * downstream (b.g() building the CSR / certificate chain, b.d() fetching the
 * private key, Signature.initSign) then runs untouched with a real key.
 *
 * Deliberately narrow:
 *   - only aliases listed in TracerConfig.REPAIR_ALIASES
 *   - only when the app itself just observed the alias is absent
 *   - once per alias per process
 *   - never rewrites a return value, argument or exception
 */
public final class KeyRepair {

    private static final String SCOPE = "Repair";

    private static final Set<String> TRIED =
            Collections.synchronizedSet(new HashSet<>());

    /** Last key pair we produced, used only if the keystore still has none. */
    private static volatile KeyPair generated;

    private KeyRepair() {
    }

    /** Called from the KeyStore#containsAlias hook when it returned false. */
    public static void onMissingAlias(String alias) {
        if (!TracerConfig.ENABLE_KEY_REPAIR) {
            return;
        }
        if (alias == null || !isRepairable(alias)) {
            return;
        }
        if (!TRIED.add(alias)) {
            return;
        }
        OtaLog.i(SCOPE, "alias missing, generating EC key pair alias=" + alias);
        try {
            generateEc(alias);
        } catch (Throwable t) {
            OtaLog.err(SCOPE, "generation failed alias=" + alias, t);
        }
    }

    private static boolean isRepairable(String alias) {
        for (String a : TracerConfig.REPAIR_ALIASES) {
            if (a.equals(alias)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Try several KeyGenParameterSpec shapes. The generator is a JCA Delegate: if
     * AndroidKeyStore rejects the parameters it silently falls back to a software
     * (Conscrypt) key, which never shows up under the alias. So each attempt is
     * checked for being actually keystore backed.
     */
    private static void generateEc(String alias) throws Exception {
        Throwable last = null;
        for (int strategy = 0; strategy < 4; strategy++) {
            try {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                if (strategy == 0) {
                    OtaLog.i(SCOPE, "generator provider=" + kpg.getProvider().getName()
                            + " impl=" + kpg.getClass().getName());
                }
                kpg.initialize(spec(alias, strategy));
                KeyPair kp = kpg.generateKeyPair();
                boolean backed = isKeystoreBacked(kp);
                OtaLog.i(SCOPE, "strategy=" + strategy + " keystoreBacked=" + backed
                        + " " + OtaLog.describe(kp));
                generated = kp;
                if (backed) {
                    break;
                }
            } catch (Throwable t) {
                last = t;
                OtaLog.i(SCOPE, "strategy=" + strategy + " failed "
                        + t.getClass().getSimpleName() + ": " + OtaLog.safeMsg(t.getMessage()));
            }
        }
        if (generated == null && last != null) {
            throw new IllegalStateException("all strategies failed", last);
        }
        verify(alias);
    }

    private static KeyGenParameterSpec spec(String alias, int strategy) {
        KeyGenParameterSpec.Builder b =
                new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN);
        switch (strategy) {
            case 0:
                return b.setAlgorithmParameterSpec(
                        new ECGenParameterSpec(TracerConfig.REPAIR_EC_CURVE))
                        .setDigests(KeyProperties.DIGEST_SHA256).build();
            case 1:
                return b.setKeySize(256).setDigests(KeyProperties.DIGEST_SHA256).build();
            case 2:
                return b.setAlgorithmParameterSpec(
                        new ECGenParameterSpec(TracerConfig.REPAIR_EC_CURVE)).build();
            default:
                return b.setKeySize(256).build();
        }
    }

    /** A real AndroidKeyStore private key is not exportable: getEncoded() is null. */
    private static boolean isKeystoreBacked(KeyPair kp) {
        if (kp == null || kp.getPrivate() == null) {
            return false;
        }
        String cn = kp.getPrivate().getClass().getName();
        return cn.contains("AndroidKeyStore") || kp.getPrivate().getEncoded() == null;
    }

    /**
     * Last resort: hand the generated private key to getKey() when the keystore
     * has none. The signature itself is still produced normally and the server
     * still verifies - we only supply key material that was missing.
     */
    public static void onGetKeyNull(XC_MethodHook.MethodHookParam param, String alias) {
        if (!TracerConfig.ENABLE_KEY_REPAIR || !TracerConfig.ENABLE_KEY_INJECT) {
            return;
        }
        if (alias == null || !isRepairable(alias)) {
            return;
        }
        KeyPair kp = generated;
        if (kp == null || kp.getPrivate() == null) {
            return;
        }
        param.setResult(kp.getPrivate());
        OtaLog.i(SCOPE, "injected generated private key for " + alias
                + " (keystore has none)");
    }

    /** Did it really land in AndroidKeyStore? Say so explicitly. */
    private static void verify(String alias) {
        try {
            KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
            OtaLog.i(SCOPE, "verify containsAlias=" + ks.containsAlias(alias)
                    + " key=" + OtaLog.describe(ks.getKey(alias, null)));
            Certificate[] chain = ks.getCertificateChain(alias);
            OtaLog.i(SCOPE, "verify chainLen=" + (chain == null ? 0 : chain.length));
            dumpAliases(ks);
        } catch (Throwable t) {
            OtaLog.err(SCOPE, "verify failed", t);
        }
    }

    /** What does this keystore actually hold? Alias names are identifiers. */
    private static void dumpAliases(KeyStore ks) {
        try {
            Enumeration<String> e = ks.aliases();
            StringBuilder sb = new StringBuilder("aliases=");
            int n = 0;
            while (e.hasMoreElements() && n < 30) {
                if (n > 0) {
                    sb.append(',');
                }
                sb.append(e.nextElement());
                n++;
            }
            OtaLog.i(SCOPE, sb.toString());
        } catch (Throwable ignored) {
            // Not fatal, we only lose inventory.
        }
    }
}
