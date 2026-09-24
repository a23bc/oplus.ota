package com.a23bc.oplus.otatracer;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Collections;
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

    private static void generateEc(String alias) throws Exception {
        KeyPairGenerator kpg =
                KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
        kpg.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(new ECGenParameterSpec(TracerConfig.REPAIR_EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build());
        KeyPair kp = kpg.generateKeyPair();
        // describe() prints algorithm/class/format only - never key material.
        OtaLog.i(SCOPE, "generated alias=" + alias + " " + OtaLog.describe(kp));
    }
}
