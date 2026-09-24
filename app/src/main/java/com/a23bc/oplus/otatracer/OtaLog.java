package com.a23bc.oplus.otatracer;

import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Key;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Single logging front door.
 *
 * Hard rules enforced here:
 *  - every line carries the same TAG so `logcat -s OplusOtaTracer` is enough;
 *  - no private key material, signature bytes, tokens or passwords are ever printed;
 *    only class names, lengths, null-ness and one-way digests;
 *  - long payloads (stack traces) are chunked, logcat truncates at ~4k.
 */
public final class OtaLog {

    public static final String TAG = "OplusOtaTracer";

    /** logcat single-line budget, leave headroom under the 4096 byte cap. */
    private static final int MAX_CHUNK = 3000;

    private static final AtomicInteger SEQ = new AtomicInteger(0);
    private static final long T0 = System.currentTimeMillis();

    /** Guard so our own output cannot re-enter {@link LogTracer}. */
    static final ThreadLocal<Boolean> SELF_LOG = new ThreadLocal<>();

    /**
     * True when the current call stack belongs to the OTA app. Used to keep
     * shared-class hooks (KeyStore, HttpURLConnection, Log) from printing noise
     * coming from framework or library code.
     */
    public static boolean callerIsTargetApp() {
        StackTraceElement[] st = new Throwable().getStackTrace();
        for (StackTraceElement e : st) {
            if (e.getClassName().startsWith(TracerConfig.TARGET_PACKAGE)) {
                return true;
            }
        }
        return false;
    }

    private OtaLog() {
    }

    // ------------------------------------------------------------------ public

    public static void i(String scope, String msg) {
        emit(scope, msg);
    }

    public static void w(String scope, String msg) {
        emit(scope, msg);
    }

    /** Log a failure once guarded by the caller; never throws. */
    public static void err(String scope, String msg, Throwable t) {
        emit(scope, msg + " ex=" + describe(t));
        if (t != null) {
            stack(scope, "throwable", t);
        }
    }

    /** Print an exception class + message + stack trace, chunked. */
    public static void stack(String scope, String label, Throwable t) {
        if (t == null) {
            return;
        }
        emit(scope, label + " " + t.getClass().getName() + ": " + safeMsg(t.getMessage()));
        StringBuilder sb = new StringBuilder();
        StackTraceElement[] st = t.getStackTrace();
        int depth = Math.min(st.length, 25);
        for (int i = 0; i < depth; i++) {
            sb.append("    at ").append(st[i].toString()).append('\n');
        }
        Throwable c = t.getCause();
        int hops = 0;
        while (c != null && hops++ < 3) {
            sb.append("  Caused by: ").append(c.getClass().getName())
                    .append(": ").append(safeMsg(c.getMessage())).append('\n');
            StackTraceElement[] cs = c.getStackTrace();
            int cd = Math.min(cs.length, 15);
            for (int i = 0; i < cd; i++) {
                sb.append("    at ").append(cs[i].toString()).append('\n');
            }
            c = c.getCause();
        }
        emitChunked(scope, sb.toString());
    }

    /** Print the current call site, skipping our own frames. */
    public static void trace(String scope, String label, int maxFrames) {
        StackTraceElement[] st = new Throwable().getStackTrace();
        StringBuilder sb = new StringBuilder();
        int kept = 0;
        for (StackTraceElement e : st) {
            String cn = e.getClassName();
            if (cn.startsWith("com.a23bc.oplus.otatracer.")
                    || cn.startsWith("de.robv.android.xposed.")
                    || cn.startsWith("io.github.libxposed.")) {
                continue;
            }
            sb.append("    at ").append(e.toString()).append('\n');
            if (++kept >= maxFrames) {
                break;
            }
        }
        emitChunked(scope, label + " stack:\n" + sb);
    }

    // ------------------------------------------------------------- describing

    /** Type-only, null-safe rendering of an arbitrary argument or return value. */
    public static String describe(Object o) {
        if (o == null) {
            return "null";
        }
        if (o instanceof Key) {
            return describeKey((Key) o);
        }
        if (o instanceof Class<?>) {
            return "class " + ((Class<?>) o).getName();
        }
        if (o instanceof Throwable) {
            Throwable t = (Throwable) o;
            return t.getClass().getName() + ": " + safeMsg(t.getMessage());
        }
        if (o instanceof byte[]) {
            return "byte[" + ((byte[]) o).length + "]";
        }
        if (o instanceof char[]) {
            // passwords / passphrases live here, never print contents.
            return "char[" + ((char[]) o).length + "]";
        }
        if (o instanceof String) {
            String s = (String) o;
            return "String(len=" + s.length() + ",shape=" + shape(s) + ",sha256:" + digest(s) + ")";
        }
        if (o instanceof Number || o instanceof Boolean || o instanceof Character) {
            return o.getClass().getSimpleName() + "(" + o + ")";
        }
        // Unknown object: class name only. Never toString() - it may leak secrets.
        return o.getClass().getName();
    }

    /** Expanded rendering for java.security.Key, the whole point of question A/B. */
    public static String describeKey(Key k) {
        if (k == null) {
            return "Key(null)";
        }
        byte[] enc = null;
        try {
            enc = k.getEncoded();
        } catch (Throwable ignored) {
            // AndroidKeyStore keys throw on getEncoded(); that itself is a signal.
        }
        return "Key class=" + k.getClass().getName()
                + " algorithm=" + safeMsg(k.getAlgorithm())
                + " format=" + safeMsg(k.getFormat())
                + " encodedLen=" + (enc == null ? "null" : String.valueOf(enc.length));
    }

    public static String safeMsg(String s) {
        if (s == null) {
            return "null";
        }
        // Cap length; messages are diagnostic but can be arbitrarily long.
        return s.length() > 300 ? s.substring(0, 300) + "...(+" + (s.length() - 300) + ")" : s;
    }

    /** Coarse shape classifier: enough to tell a PEM blob from a numeric id. */
    private static String shape(String s) {
        if (s.isEmpty()) {
            return "empty";
        }
        boolean hex = true;
        boolean b64 = true;
        boolean digits = true;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (digits && !Character.isDigit(c)) {
                digits = false;
            }
            if (hex && !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                hex = false;
            }
            if (b64 && !(Character.isLetterOrDigit(c) || c == '+' || c == '/' || c == '=')) {
                b64 = false;
            }
        }
        if (digits) {
            return "numeric";
        }
        if (hex) {
            return "hex";
        }
        if (b64) {
            return "base64ish";
        }
        return "text";
    }

    /** One-way, truncated. Never reversible to the source string. */
    public static String digest(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 8 && i < d.length; i++) {
                sb.append(String.format("%02x", d[i]));
            }
            return sb.toString();
        } catch (Throwable t) {
            return "na";
        }
    }

    // ------------------------------------------------------------------ output

    private static void emit(String scope, String msg) {
        String line = prefix() + "[" + scope + "] " + msg;
        if (line.length() <= MAX_CHUNK) {
            write(line);
            return;
        }
        emitChunked(scope, msg);
    }

    private static void emitChunked(String scope, String text) {
        String p = prefix() + "[" + scope + "] ";
        int i = 0;
        int part = 0;
        while (i < text.length()) {
            int end = Math.min(text.length(), i + MAX_CHUNK);
            write(p + "(part" + part + ") " + text.substring(i, end));
            i = end;
            part++;
        }
    }

    private static String prefix() {
        return "seq=" + SEQ.incrementAndGet() + " t=+" + (System.currentTimeMillis() - T0) + "ms ";
    }

    private static void write(String line) {
        Boolean self = SELF_LOG.get();
        SELF_LOG.set(Boolean.TRUE);
        try {
            Log.d(TAG, line);
        } finally {
            if (self == null) {
                SELF_LOG.remove();
            } else {
                SELF_LOG.set(self);
            }
        }
    }
}
