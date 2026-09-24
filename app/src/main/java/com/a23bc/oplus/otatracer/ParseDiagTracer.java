package com.a23bc.oplus.otatracer;

import android.os.Handler;
import android.os.Looper;

import java.lang.reflect.Method;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * r14: find out which check between the CryptoEng answer and generateX509() fails.
 *
 * r13 left the chain at:
 *   pkiCommonAsk() -> byte[2512] -> ??? -> generate() -> generateX509() = null
 *
 * The "???" is the SDK's own verdict over that buffer. Three methods decide it:
 *   ResultParser.parse(byte[])          - turn the buffer into a result object
 *   Util.isParseSuccess(...)            - did the buffer parse at all
 *   Util.isMethodExecuteSuccessV2(...)  - did the TA itself report success
 *
 * This tracer is strictly observational. It hooks exactly those three method
 * names, on the classes that declare them, and records:
 *   - argument types only (byte[] length, String length+digest - never contents)
 *   - return type, null-ness and, for booleans, the value
 *   - exception class + message when one is thrown
 *
 * It never calls setResult, never touches param.args, never clears a throwable,
 * and does not fall back to anything when a check fails.
 */
public final class ParseDiagTracer {

    private static final String SCOPE = "Parse";

    /**
     * These two pin down the SDK's Util class beyond doubt; "parse" alone is too
     * common a name to hook on a class just because it is called Util.
     */
    private static final String[] STRICT_METHODS = {
            "isParseSuccess", "isMethodExecuteSuccessV2",
    };

    private static boolean installed = false;
    private static volatile ClassLoader appCl;

    /** A class reached by FQCN must not be hooked again by the simple-name scan. */
    private static final java.util.Set<String> SEEN =
            java.util.Collections.synchronizedSet(new java.util.HashSet<>());

    /** Cap on "this check failed" stacks, so a retry loop cannot flood logcat. */
    private static final ConcurrentHashMap<String, AtomicInteger> VERDICT_STACKS =
            new ConcurrentHashMap<>();

    private ParseDiagTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        appCl = lpparam.classLoader;

        int hooked = 0;
        for (String fqcn : TracerConfig.PARSE_DIAG_CLASS_CANDIDATES) {
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
            hooked += attach(c, "fqcn");
        }

        if (hooked == 0) {
            OtaLog.i(SCOPE, "no FQCN hit, will scan by simple name");
        }
        scheduleScan();
    }

    /** Off-thread: the FQCN guesses are just guesses. */
    private static void scheduleScan() {
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            for (String simple : TracerConfig.PARSE_DIAG_SIMPLE_NAMES) {
                                List<Class<?>> found = ClassHunter.findBySimpleName(simple,
                                        TracerConfig.PARSE_DIAG_MAX_CLASSES);
                                for (Class<?> c : found) {
                                    OtaLog.i(SCOPE, "candidate " + c.getName());
                                    attach(c, "simpleName=" + simple);
                                }
                            }
                        } catch (Throwable t) {
                            OtaLog.err(SCOPE, "scan failed", t);
                        }
                    }
                }, "OtaTracer-parsediag").start();
            }
        }, TracerConfig.PARSE_DIAG_SCAN_DELAY_MS);
    }

    /**
     * Hook the three r14 methods if this class really declares them.
     *
     * Scope guard: "parse" is only hooked when the class is part of the
     * cryptography SDK or is actually named ResultParser - otherwise a random
     * Util.parse(String) would end up hooked. The two isXxxSuccessV2 methods are
     * specific enough to hook wherever they appear.
     */
    private static int attach(Class<?> c, String via) {
        if (!SEEN.add(c.getName())) {
            return 0;
        }
        Method[] ms;
        try {
            ms = c.getDeclaredMethods();
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "cannot list methods of " + c.getName());
            return 0;
        }
        if (ms == null) {
            return 0;
        }

        boolean strict = false;
        for (Method m : ms) {
            for (String s : STRICT_METHODS) {
                if (m.getName().equals(s)) {
                    strict = true;
                }
            }
        }
        boolean allawn = c.getName().toLowerCase().contains("allawn");
        boolean namedResultParser = c.getSimpleName().contains("ResultParser");

        int hooked = 0;
        for (String want : TracerConfig.PARSE_DIAG_METHODS) {
            boolean present = false;
            for (Method m : ms) {
                if (m.getName().equals(want)) {
                    present = true;
                    break;
                }
            }
            if (!present) {
                continue;
            }
            if ("parse".equals(want) && !strict && !(allawn || namedResultParser)) {
                OtaLog.i(SCOPE, "skip parse on " + c.getName() + " (not the SDK ResultParser)");
                continue;
            }
            hooked += ClassHunter.hookAllByName(c, want, new ParseCallback(), SCOPE);
        }
        if (hooked > 0) {
            OtaLog.i(SCOPE, "attached " + c.getName() + " via=" + via + " overloads=" + hooked);
        }
        return hooked;
    }

    private static boolean isVoid(java.lang.reflect.Member m) {
        return m instanceof Method && ((Method) m).getReturnType() == void.class;
    }

    /** First N failures per method get a caller stack: shows who consumed it. */
    private static boolean verdictStackBudget(String name) {
        AtomicInteger counter = VERDICT_STACKS.get(name);
        if (counter == null) {
            counter = new AtomicInteger(0);
            AtomicInteger prev = VERDICT_STACKS.putIfAbsent(name, counter);
            if (prev != null) {
                counter = prev;
            }
        }
        return counter.getAndIncrement() < TracerConfig.PARSE_DIAG_MAX_VERDICT_STACKS;
    }

    private static final class ParseCallback extends XC_MethodHook {

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
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "before logging failed", t);
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                String name = param.method.getName();

                if (param.hasThrowable()) {
                    Throwable th = param.getThrowable();
                    OtaLog.i(SCOPE, name + " threw ex=" + (th == null
                            ? "null"
                            : th.getClass().getName() + ": " + OtaLog.safeMsg(th.getMessage())));
                    OtaLog.stack(SCOPE, name + " exception:", th);
                    return;
                }

                Object r = param.getResult();
                StringBuilder sb = new StringBuilder(name).append(" return ")
                        .append(OtaLog.describe(r));
                if (isVoid(param.method)) {
                    sb.append(" void=true");
                } else {
                    sb.append(" type=").append(r == null ? "null" : r.getClass().getName())
                            .append(" isNull=").append(r == null);
                }
                OtaLog.i(SCOPE, sb.toString());

                // A false / null verdict is the answer to "which check failed".
                boolean failed = !isVoid(param.method)
                        && (r == null || Boolean.FALSE.equals(r));
                if (failed && verdictStackBudget(name)) {
                    OtaLog.trace(SCOPE, name + " verdict caller", 8);
                }
            } catch (Throwable t) {
                OtaLog.err(SCOPE, "after logging failed", t);
            }
        }
    }
}
