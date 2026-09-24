package com.a23bc.oplus.otatracer;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.atomic.AtomicInteger;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Finds the download thread even when its class is obfuscated.
 *
 * The first trace showed the whole download flow running inside `u7.a.run()` on a
 * ThreadPoolExecutor worker - no class name to grep for. So instead of guessing,
 * this watches the two places where work actually starts (Thread#start and
 * ThreadPoolExecutor#execute), reports the OTA-owned classes it sees, and hooks
 * run() on a capped number of them.
 *
 * Read-only, and deliberately narrow: only classes under com.oplus.ota, at most
 * MAX_TRACED run() hooks.
 */
public final class ThreadTracer {

    private static final String SCOPE = "Thread";

    private static final int MAX_TRACED = 20;

    private static final Set<String> HOOKED =
            Collections.synchronizedSet(new HashSet<>());
    private static final AtomicInteger COUNT = new AtomicInteger(0);

    private static boolean installed = false;

    private ThreadTracer() {
    }

    public static void install(XC_LoadPackage.LoadPackageParam lpparam) {
        if (installed) {
            return;
        }
        installed = true;
        try {
            XposedHelpers.findAndHookMethod(Thread.class, "start", new StartCallback());
            OtaLog.i(SCOPE, "hooked java.lang.Thread#start");
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable Thread#start ("
                    + t.getClass().getSimpleName() + ")");
        }
        try {
            XposedHelpers.findAndHookMethod(ThreadPoolExecutor.class, "execute",
                    Runnable.class, new ExecuteCallback());
            OtaLog.i(SCOPE, "hooked ThreadPoolExecutor#execute");
        } catch (Throwable t) {
            OtaLog.i(SCOPE, "hook unavailable ThreadPoolExecutor#execute ("
                    + t.getClass().getSimpleName() + ")");
        }
    }

    /**
     * "Ours" means shipped by the app, not by the framework. A package prefix
     * test is not enough: obfuscation renames top-level packages to single
     * letters (u7.a, b7.c, s9.b), so class loader identity is used instead -
     * boot classes have a null loader. Known library prefixes are excluded too.
     */
    private static boolean isOurs(Class<?> clazz) {
        if (clazz.getClassLoader() == null) {
            return false;
        }
        String cn = clazz.getName();
        for (String lib : TracerConfig.LIBRARY_PREFIXES) {
            if (cn.startsWith(lib)) {
                return false;
            }
        }
        return true;
    }

    /** Report + trace an OTA-owned runnable/thread class, once each. */
    private static void note(Class<?> clazz, String label) {
        String cn = clazz.getName();
        boolean ours = isOurs(clazz);
        OtaLog.i(SCOPE, label + " class=" + cn + " ours=" + ours);
        if (!ours) {
            return;
        }
        if (!HOOKED.add(cn)) {
            return;
        }
        if (COUNT.incrementAndGet() > MAX_TRACED) {
            OtaLog.i(SCOPE, "run() hook budget reached, skipping " + cn);
            return;
        }
        ClassHunter.hookAllByName(clazz, "run", new RunCallback(cn), SCOPE);
    }

    private static final class StartCallback extends XC_MethodHook {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Object thiz = param.thisObject;
                if (thiz instanceof Thread) {
                    Thread t = (Thread) thiz;
                    note(t.getClass(), "start name=" + t.getName());
                }
            } catch (Throwable ignored) {
                // Never break thread startup.
            }
        }
    }

    private static final class ExecuteCallback extends XC_MethodHook {
        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                Object arg0 = param.args != null && param.args.length > 0 ? param.args[0] : null;
                if (arg0 instanceof Runnable) {
                    note(arg0.getClass(), "execute");
                }
            } catch (Throwable ignored) {
                // Never break task submission.
            }
        }
    }

    private static final class RunCallback extends XC_MethodHook {

        private final String cn;

        RunCallback(String cn) {
            this.cn = cn;
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            try {
                OtaLog.i(SCOPE, "run enter " + cn);
            } catch (Throwable ignored) {
            }
        }

        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            try {
                if (param.hasThrowable()) {
                    OtaLog.i(SCOPE, "run threw " + cn);
                    OtaLog.stack(SCOPE, "run exception " + cn + ":", param.getThrowable());
                    return;
                }
                OtaLog.i(SCOPE, "run exit " + cn);
            } catch (Throwable ignored) {
            }
        }
    }
}
