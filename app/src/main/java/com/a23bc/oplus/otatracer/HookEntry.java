package com.a23bc.oplus.otatracer;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Entry point declared in assets/xposed_init.
 *
 * Scope discipline: the module installs hooks only inside com.oplus.ota
 * (which covers the com.oplus.ota:ui process as well). Any other package is
 * left completely untouched.
 *
 * This is a pure observer. No hook in this module calls setResult(), mutates
 * param.args, or sets/clears a throwable, so the OTA app's download behaviour,
 * signature verification, integrity checks and server responses are unchanged.
 */
public final class HookEntry implements IXposedHookLoadPackage {

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam lpparam) throws Throwable {
        if (lpparam == null || !TracerConfig.TARGET_PACKAGE.equals(lpparam.packageName)) {
            return;
        }

        OtaLog.i("Boot", "attach process=" + lpparam.processName
                + " pkg=" + lpparam.packageName
                + " isFirstApp=" + lpparam.isFirstApplication);

        // Register what we are looking for first...
        AttestationTracer.install(lpparam);
        SignVerifyTracer.install(lpparam);
        GetInfoThreadTracer.install(lpparam);
        DownloadExceptionTracer.install(lpparam);

        // ...then resolve the known FQCNs and schedule the background scans.
        // Class loading itself is never hooked - see ClassHunter.
        ClassHunter.install(lpparam);

        // Shared-class hooks, self-filtered to the OTA call stack.
        if (TracerConfig.ENABLE_SHARED_CLASS_HOOKS) {
            ResponseCodeTracer.install(lpparam);
            KeyStoreTracer.install(lpparam);
            SpTracer.install(lpparam);
            ThreadTracer.install(lpparam);
            if (TracerConfig.ENABLE_LOG_ECHO) {
                LogTracer.install(lpparam);
            }
        }

        OtaLog.i("Boot", "install complete - filter with: logcat -s OplusOtaTracer");
    }
}
