package com.a23bc.oplus.otatracer;

import android.os.Handler;
import android.os.Looper;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Finds the classes the tracer needs without knowing their obfuscated name.
 *
 * Discovery paths, all fail-safe:
 *   1. explicit FQCN guesses, resolved immediately (cheap, unobfuscated builds)
 *   2. keyword dex scan: class-name substrings only, background thread
 *   3. deep dex scan: load com.oplus.ota classes and match declared method names,
 *      background thread, rate limited and time boxed, only if SignVerifyUtils
 *      was still unresolved
 *
 * IMPORTANT: nothing reflective runs on the main thread and class loading is
 * never hooked. An earlier version hooked ClassLoader#loadClass and called
 * getDeclaredMethods() inside its callback; that triggered nested class loading
 * and corrupted the app class loader (every later findClass failed and the :ui
 * process hung on a black screen). Do not reintroduce it.
 */
public final class ClassHunter {

    public interface ClassVisitor {
        /** Called at most once per class. Must not throw. */
        void onClass(Class<?> clazz);
    }

    private static final Set<String> SEEN = Collections.synchronizedSet(new HashSet<>());
    private static final Set<String> HIT_RULES = Collections.synchronizedSet(new HashSet<>());
    /** Rules that actually got their target methods hooked. */
    private static final Set<String> SATISFIED = Collections.synchronizedSet(new HashSet<>());
    private static final List<Rule> RULES = Collections.synchronizedList(new ArrayList<>());

    private static final Handler MAIN = new Handler(Looper.getMainLooper());

    private static volatile ClassLoader appClassLoader;
    private static volatile boolean installed = false;
    private static volatile boolean scanStopped = false;

    private ClassHunter() {
    }

    private static final class Rule {
        final String name;
        final String[] fqcnCandidates;
        final String[] methodNames;     // exact declared-method names, any of them
        final String[] simpleNameHints; // case-insensitive substrings of the simple name
        final ClassVisitor visitor;

        Rule(String name, String[] fqcnCandidates, String[] methodNames,
             String[] simpleNameHints, ClassVisitor visitor) {
            this.name = name;
            this.fqcnCandidates = fqcnCandidates;
            this.methodNames = methodNames;
            this.simpleNameHints = simpleNameHints;
            this.visitor = visitor;
        }
    }

    public static void watch(String ruleName,
                             String[] fqcnCandidates,
                             String[] methodNames,
                             String[] simpleNameHints,
                             ClassVisitor visitor) {
        RULES.add(new Rule(ruleName, fqcnCandidates, methodNames, simpleNameHints, visitor));
        OtaLog.i("Hunter", "rule registered name=" + ruleName);
    }

    /**
     * Call after every rule is registered: resolves the known FQCNs and schedules
     * the background scans plus a heartbeat.
     */
    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        appClassLoader = lpparam.classLoader;

        resolveKnown(lpparam);

        if (!TracerConfig.ENABLE_DEX_SCAN) {
            OtaLog.i("Hunter", "dex scans disabled by config");
            return;
        }

        MAIN.postDelayed(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            keywordScan();
                        } catch (Throwable t) {
                            OtaLog.err("Hunter", "keyword scan failed", t);
                        }
                    }
                }, "OtaTracer-kwscan").start();
            }
        }, TracerConfig.DEX_SCAN_DELAY_MS);

        MAIN.postDelayed(new Runnable() {
            @Override
            public void run() {
                // "Resolved" is not enough: the first run matched only the inner
                // class SignVerifyUtils$ByteArrayComparator, which has none of the
                // methods we need. Only a hooked target method counts.
                if (SATISFIED.contains("SignVerifyUtils")) {
                    OtaLog.i("Hunter", "deep scan skipped: ecdsaSignPki already hooked");
                    return;
                }
                OtaLog.i("Hunter", "deep scan starting: ecdsaSignPki not hooked yet");
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            deepScan();
                        } catch (Throwable t) {
                            OtaLog.err("Hunter", "deep scan failed", t);
                        }
                    }
                }, "OtaTracer-dpscan").start();
            }
        }, TracerConfig.DEEP_SCAN_DELAY_MS);

        startHeartbeat();
    }

    /** Heartbeat makes a hang visible: the last printed seq is where it froze. */
    private static void startHeartbeat() {
        final int[] left = {TracerConfig.HEARTBEAT_COUNT};
        MAIN.postDelayed(new Runnable() {
            @Override
            public void run() {
                OtaLog.i("Boot", "heartbeat left=" + left[0]
                        + " rulesHit=" + new ArrayList<>(HIT_RULES)
                        + " scanStopped=" + scanStopped);
                left[0]--;
                if (left[0] > 0) {
                    MAIN.postDelayed(this, TracerConfig.HEARTBEAT_INTERVAL_MS);
                }
            }
        }, TracerConfig.HEARTBEAT_INTERVAL_MS);
    }

    // ------------------------------------------------------------- resolution

    public static void resolveKnown(XC_LoadPackage.LoadPackageParam lpparam) {
        for (Rule r : new ArrayList<>(RULES)) {
            if (r.fqcnCandidates == null) {
                continue;
            }
            for (String fqcn : r.fqcnCandidates) {
                Class<?> c;
                try {
                    c = XposedHelpers.findClassIfExists(fqcn, lpparam.classLoader);
                } catch (Throwable t) {
                    c = null;
                }
                if (c != null) {
                    deliver(r, c, "fqcn");
                } else {
                    OtaLog.i("Hunter", "no class " + fqcn);
                }
            }
        }
    }

    private static boolean matches(Rule r, Class<?> clazz) {
        String simple = clazz.getSimpleName();
        String lower = simple == null ? "" : simple.toLowerCase();

        if (r.simpleNameHints != null) {
            for (String hint : r.simpleNameHints) {
                if (lower.contains(hint.toLowerCase())) {
                    return true;
                }
            }
        }
        if (r.methodNames != null && r.methodNames.length > 0) {
            Method[] ms;
            try {
                ms = clazz.getDeclaredMethods();
            } catch (Throwable t) {
                return false; // unresolvable signatures while linking
            }
            if (ms != null) {
                for (Method m : ms) {
                    for (String want : r.methodNames) {
                        if (m.getName().equals(want)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private static void deliver(Rule r, Class<?> clazz, String via) {
        if (!SEEN.add(r.name + "|" + clazz.getName())) {
            return;
        }
        HIT_RULES.add(r.name);
        OtaLog.i("Hunter", "hit rule=" + r.name + " class=" + clazz.getName() + " via=" + via);
        try {
            r.visitor.onClass(clazz);
        } catch (Throwable t) {
            OtaLog.err("Hunter", "visitor failed rule=" + r.name + " class=" + clazz.getName(), t);
        }
    }

    // ------------------------------------------------------------- dex scans

    /** Enumerate dex entries; only class-name filtering decides what to load. */
    private static void keywordScan() {
        ClassLoader cl = appClassLoader;
        if (cl == null) {
            return;
        }
        Enumeration<String> names = dexEntries(cl);
        if (names == null) {
            OtaLog.i("Hunter", "keyword scan skipped: no dex entries");
            return;
        }
        int scanned = 0;
        int candidates = 0;
        while (names.hasMoreElements() && !scanStopped) {
            String cn = names.nextElement();
            scanned++;
            if (!isInterestingName(cn)) {
                continue;
            }
            candidates++;
            consider(cn, cl, "keyword");
            sleepQuietly(TracerConfig.SCAN_YIELD_MS);
        }
        OtaLog.i("Hunter", "keyword scan done scanned=" + scanned + " candidates=" + candidates);
    }

    /**
     * Try a class, and if it is an inner class also its outer one. The dex scan
     * once found only SignVerifyUtils$ByteArrayComparator and missed the real
     * SignVerifyUtils.
     */
    private static void consider(String cn, ClassLoader cl, String via) {
        tryClass(cn, cl, via);
        int dollar = cn.indexOf('$');
        if (dollar > 0) {
            tryClass(cn.substring(0, dollar), cl, via + "-outer");
        }
    }

    private static void tryClass(String cn, ClassLoader cl, String via) {
        Class<?> c;
        try {
            c = Class.forName(cn, false, cl);
        } catch (Throwable t) {
            OtaLog.i("Hunter", "candidate load failed " + cn
                    + " (" + t.getClass().getSimpleName() + ")");
            return;
        }
        for (Rule r : new ArrayList<>(RULES)) {
            if (matches(r, c)) {
                deliver(r, c, via);
            }
        }
    }

    /**
     * Obfuscation fallback: load com.oplus.ota classes and match declared method
     * names. Rate limited and time boxed, background thread only.
     */
    private static void deepScan() {
        ClassLoader cl = appClassLoader;
        if (cl == null) {
            return;
        }
        Enumeration<String> names = dexEntries(cl);
        if (names == null) {
            OtaLog.i("Hunter", "deep scan skipped: no dex entries");
            return;
        }
        long deadline = System.currentTimeMillis() + TracerConfig.DEEP_SCAN_BUDGET_MS;
        int loaded = 0;
        int checked = 0;
        while (names.hasMoreElements() && !scanStopped) {
            if (System.currentTimeMillis() > deadline) {
                OtaLog.i("Hunter", "deep scan budget exhausted loaded=" + loaded);
                scanStopped = true;
                break;
            }
            String cn = names.nextElement();
            if (!cn.startsWith(TracerConfig.TARGET_PACKAGE)) {
                continue;
            }
            Class<?> c;
            try {
                c = Class.forName(cn, false, cl);
            } catch (Throwable t) {
                continue;
            }
            loaded++;
            if (++checked % TracerConfig.DEEP_SCAN_BATCH == 0) {
                sleepQuietly(TracerConfig.SCAN_YIELD_MS);
            }
            for (Rule r : new ArrayList<>(RULES)) {
                if (r.methodNames == null || r.methodNames.length == 0) {
                    continue;
                }
                if (matches(r, c)) {
                    deliver(r, c, "deep");
                }
            }
        }
        OtaLog.i("Hunter", "deep scan done loaded=" + loaded + " checked=" + checked);
    }

    private static Enumeration<String> dexEntries(ClassLoader cl) {
        Object pathList;
        try {
            pathList = XposedHelpers.getObjectField(cl, "pathList");
        } catch (Throwable t) {
            OtaLog.i("Hunter", "no pathList on " + cl.getClass().getName());
            return null;
        }
        Object[] elements;
        try {
            elements = (Object[]) XposedHelpers.getObjectField(pathList, "dexElements");
        } catch (Throwable t) {
            OtaLog.i("Hunter", "no dexElements");
            return null;
        }
        if (elements == null) {
            return null;
        }
        final List<Enumeration<String>> enums = new ArrayList<>();
        for (Object element : elements) {
            if (element == null) {
                continue;
            }
            Object dexFileObj;
            try {
                dexFileObj = XposedHelpers.getObjectField(element, "dexFile");
            } catch (Throwable t) {
                continue;
            }
            if (dexFileObj == null) {
                continue;
            }
            try {
                Object e = dexFileObj.getClass().getMethod("entries").invoke(dexFileObj);
                if (e instanceof Enumeration<?>) {
                    enums.add((Enumeration<String>) e);
                }
            } catch (Throwable ignored) {
                // Element shape differs on some ROMs; nothing to do.
            }
        }
        if (enums.isEmpty()) {
            return null;
        }
        return new Enumeration<String>() {
            int idx = 0;

            @Override
            public boolean hasMoreElements() {
                while (idx < enums.size()) {
                    if (enums.get(idx).hasMoreElements()) {
                        return true;
                    }
                    idx++;
                }
                return false;
            }

            @Override
            public String nextElement() {
                return enums.get(idx).nextElement();
            }
        };
    }

    private static boolean isInterestingName(String cn) {
        String n = cn.toLowerCase();
        return n.contains("signverify") || n.contains("getinfothread")
                || n.contains("downloadexception") || n.contains("ecdsa")
                || n.contains("gka") || n.contains("signutil");
    }

    private static void sleepQuietly(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            scanStopped = true;
        }
    }

    // ------------------------------------------------------------------ hooks

    /** Called by a tracer once its target methods are really hooked. */
    public static void markSatisfied(String ruleName) {
        SATISFIED.add(ruleName);
    }

    /**
     * Hook every overload of a named method; never modifies the invocation.
     * Returns the number of hooked overloads.
     */
    public static int hookAllByName(Class<?> clazz,
                                    String methodName,
                                    XC_MethodHook callback,
                                    String scope) {
        try {
            Set<XC_MethodHook.Unhook> hooks = XposedBridge.hookAllMethods(clazz, methodName, callback);
            if (hooks.isEmpty()) {
                OtaLog.i(scope, "no method named " + methodName + " on " + clazz.getName());
                return 0;
            }
            OtaLog.i(scope, "hooked " + methodName + " overloads=" + hooks.size()
                    + " on " + clazz.getName());
            return hooks.size();
        } catch (Throwable t) {
            OtaLog.err(scope, "hook " + methodName + " failed on " + clazz.getName(), t);
            return 0;
        }
    }

    /** Hook every constructor of a class; never modifies the invocation. */
    public static void hookAllConstructors(Class<?> clazz,
                                           XC_MethodHook callback,
                                           String scope) {
        try {
            Set<XC_MethodHook.Unhook> hooks = XposedBridge.hookAllConstructors(clazz, callback);
            if (hooks.isEmpty()) {
                OtaLog.i(scope, "no constructor on " + clazz.getName());
                return;
            }
            OtaLog.i(scope, "hooked <init> overloads=" + hooks.size() + " on " + clazz.getName());
        } catch (Throwable t) {
            OtaLog.err(scope, "hook <init> failed on " + clazz.getName(), t);
        }
    }
}
