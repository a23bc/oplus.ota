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
 * Finds the class the tracer needs without knowing its obfuscated name.
 *
 * Three independent discovery paths, all best-effort:
 *   1. explicit FQCN guesses (fast path, works on unobfuscated builds)
 *   2. a ClassLoader#loadClass hook that inspects every class as it is linked
 *      (covers renamed classes as long as the target method names survive)
 *   3. a deferred dex scan that looks for classes by name keyword + method signature
 *
 * Every path is wrapped so that a missing class is reported once and never crashes
 * the host app.
 */
public final class ClassHunter {

    public interface ClassVisitor {
        /** Called at most once per class. Must not throw. */
        void onClass(Class<?> clazz);
    }

    private static final Set<String> SEEN = Collections.synchronizedSet(new HashSet<>());
    private static final List<Rule> RULES = Collections.synchronizedList(new ArrayList<>());
    private static boolean loadClassHookInstalled = false;

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

    /**
     * Register interest in a class. Discovery starts immediately for the FQCN
     * guesses and continues lazily via the ClassLoader hook.
     */
    public static void watch(String ruleName,
                             String[] fqcnCandidates,
                             String[] methodNames,
                             String[] simpleNameHints,
                             ClassVisitor visitor) {
        Rule rule = new Rule(ruleName, fqcnCandidates, methodNames, simpleNameHints, visitor);
        RULES.add(rule);
        OtaLog.i("Hunter", "rule registered name=" + ruleName);
    }

    /** Install the lazy class-loading hook. Idempotent. */
    public static void install(final XC_LoadPackage.LoadPackageParam lpparam) {
        if (loadClassHookInstalled) {
            return;
        }
        try {
            XposedHelpers.findAndHookMethod(ClassLoader.class, "loadClass", String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                            if (param.hasThrowable()) {
                                return;
                            }
                            Object result = param.getResult();
                            if (!(result instanceof Class<?>)) {
                                return;
                            }
                            try {
                                dispatch((Class<?>) result);
                            } catch (Throwable ignored) {
                                // Never let tracing break class loading.
                            }
                        }
                    });
            loadClassHookInstalled = true;
            OtaLog.i("Hunter", "ClassLoader#loadClass hook installed");
        } catch (Throwable t) {
            OtaLog.err("Hunter", "loadClass hook failed", t);
        }

        final ClassLoader cl = lpparam.classLoader;
        // Deferred dex scan: cheap keyword pre-filter, then structural check.
        new Handler(Looper.getMainLooper()).postDelayed(new Runnable() {
            @Override
            public void run() {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            scanDexes(cl);
                        } catch (Throwable t) {
                            OtaLog.err("Hunter", "dex scan failed", t);
                        }
                    }
                }, "OtaTracer-dexscan").start();
            }
        }, 1500);
    }

    // ------------------------------------------------------------- resolution

    /** Try the explicit FQCN guesses right away (unobfuscated builds). */
    public static void resolveKnown(XC_LoadPackage.LoadPackageParam lpparam) {
        for (Rule r : new ArrayList<>(RULES)) {
            if (r.fqcnCandidates == null) {
                continue;
            }
            for (String fqcn : r.fqcnCandidates) {
                Class<?> c = null;
                try {
                    c = XposedHelpers.findClassIfExists(fqcn, lpparam.classLoader);
                } catch (Throwable ignored) {
                    c = null;
                }
                if (c != null) {
                    deliver(r, c, "fqcn");
                }
            }
        }
    }

    private static void dispatch(Class<?> clazz) {
        if (clazz == null) {
            return;
        }
        for (Rule r : new ArrayList<>(RULES)) {
            if (matches(r, clazz)) {
                deliver(r, clazz, "loadClass");
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
        if (r.methodNames != null) {
            Method[] ms;
            try {
                ms = clazz.getDeclaredMethods();
            } catch (Throwable t) {
                return false; // NoClassDefFoundError while resolving signatures
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
        OtaLog.i("Hunter", "hit rule=" + r.name + " class=" + clazz.getName() + " via=" + via);
        try {
            r.visitor.onClass(clazz);
        } catch (Throwable t) {
            OtaLog.err("Hunter", "visitor failed rule=" + r.name + " class=" + clazz.getName(), t);
        }
    }

    // ---------------------------------------------------------------- dex scan

    /**
     * Enumerate class names straight out of the dex files and structurally check
     * the promising ones. Only used as a fallback for classes already loaded
     * before our hook was in place.
     */
    private static void scanDexes(ClassLoader cl) {
        Object pathList;
        try {
            pathList = XposedHelpers.getObjectField(cl, "pathList");
        } catch (Throwable t) {
            OtaLog.i("Hunter", "dex scan skipped: no pathList on " + cl.getClass().getName());
            return;
        }
        Object[] elements;
        try {
            elements = (Object[]) XposedHelpers.getObjectField(pathList, "dexElements");
        } catch (Throwable t) {
            OtaLog.i("Hunter", "dex scan skipped: no dexElements");
            return;
        }
        if (elements == null) {
            return;
        }

        int scanned = 0;
        int candidates = 0;
        for (Object element : elements) {
            if (element == null) {
                continue;
            }
            Object dexFileObj = null;
            try {
                dexFileObj = XposedHelpers.getObjectField(element, "dexFile");
            } catch (Throwable ignored) {
                // Element shape changed on some versions; try the nested path.
            }
            if (dexFileObj == null) {
                continue;
            }
            Enumeration<String> names = null;
            try {
                names = (Enumeration<String>) dexFileObj.getClass()
                        .getMethod("entries").invoke(dexFileObj);
            } catch (Throwable ignored) {
                continue;
            }
            if (names == null) {
                continue;
            }
            while (names.hasMoreElements()) {
                String cn = names.nextElement();
                scanned++;
                if (!isInterestingName(cn)) {
                    continue;
                }
                candidates++;
                Class<?> c;
                try {
                    c = Class.forName(cn, false, cl);
                } catch (Throwable t) {
                    continue;
                }
                dispatch(c);
            }
        }
        OtaLog.i("Hunter", "dex scan done scanned=" + scanned + " candidates=" + candidates);
    }

    /** Cheap string pre-filter so we do not touch thousands of classes. */
    private static boolean isInterestingName(String cn) {
        String n = cn.toLowerCase();
        return n.contains("signverify") || n.contains("signverifyutils")
                || n.contains("getinfothread") || n.contains("downloadexception")
                || n.contains("ecdsa") || n.contains("gka");
    }

    /** Hook every overload of a named method; never modifies the invocation. */
    public static void hookAllByName(Class<?> clazz,
                                     String methodName,
                                     XC_MethodHook callback,
                                     String scope) {
        try {
            Set<XC_MethodHook.Unhook> hooks = XposedBridge.hookAllMethods(clazz, methodName, callback);
            OtaLog.i(scope, "hooked " + methodName + " overloads=" + hooks.size()
                    + " on " + clazz.getName());
        } catch (Throwable t) {
            OtaLog.err(scope, "hook " + methodName + " failed on " + clazz.getName(), t);
        }
    }

    /** Hook every constructor of a class; never modifies the invocation. */
    public static void hookAllConstructors(Class<?> clazz,
                                           XC_MethodHook callback,
                                           String scope) {
        try {
            Set<XC_MethodHook.Unhook> hooks = XposedBridge.hookAllConstructors(clazz, callback);
            OtaLog.i(scope, "hooked <init> overloads=" + hooks.size() + " on " + clazz.getName());
        } catch (Throwable t) {
            OtaLog.err(scope, "hook <init> failed on " + clazz.getName(), t);
        }
    }
}
