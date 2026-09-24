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

        // Discovery first: the ClassLoader hook must be live before app classes load.
        ClassHunter.install(lpparam);

        SignVerifyTracer.install(lpparam);
        GetInfoThreadTracer.install(lpparam);
        DownloadExceptionTracer.install(lpparam);

        // Fast path for unobfuscated builds: try the known FQCNs immediately.
        ClassHunter.resolveKnown(lpparam);

        // Shared-class hooks, self-filtered to the OTA call stack.
        ResponseCodeTracer.install(lpparam);
        KeyStoreTracer.install(lpparam);
        SpTracer.install(lpparam);
        LogTracer.install(lpparam);

        OtaLog.i("Boot", "install complete - filter with: logcat -s OplusOtaTracer");
    }
}
