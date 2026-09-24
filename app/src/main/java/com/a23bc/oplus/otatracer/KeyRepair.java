package com.a23bc.oplus.otatracer;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

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
        // If this is not actually the keystore-backed generator, the key ends up
        // in software (Conscrypt) and getKey() will still return null.
        OtaLog.i(SCOPE, "generator provider=" + kpg.getProvider().getName()
                + " impl=" + kpg.getClass().getName());

        KeyPair kp;
        try {
            kpg.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(new ECGenParameterSpec(TracerConfig.REPAIR_EC_CURVE))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            kp = kpg.generateKeyPair();
        } catch (Throwable t) {
            OtaLog.err(SCOPE, "curve spec rejected, retrying with key size", t);
            KeyPairGenerator alt =
                    KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
            alt.initialize(new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setKeySize(256)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build());
            kp = alt.generateKeyPair();
        }
        // describe() prints algorithm/class/format only - never key material.
        OtaLog.i(SCOPE, "generated alias=" + alias + " " + OtaLog.describe(kp));
        verify(alias);
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
