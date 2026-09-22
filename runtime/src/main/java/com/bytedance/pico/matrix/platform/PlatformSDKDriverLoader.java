package com.bytedance.pico.matrix.platform;

import android.content.Context;
import android.util.Log;

/** Existing Matrix SDK bootstrap contract. Vendor driver is supplied locally. */
public final class PlatformSDKDriverLoader {
    private static boolean loaded;
    public static synchronized long load64(Context client, Context runtime, int major, int minor, int patch, int build, int flags) {
        org.picomatrix.bridge.AccountBridge.initialize(client);
        org.picomatrix.bridge.RuntimeDiagnostics.start(client);
        if (!loaded) {
            System.loadLibrary("volcenginertc");
            System.loadLibrary("platformsdk");
            loaded=true;
        }
        long accessor=nativeGetFunctionAccessor();
        Log.i("MatrixBridge", "driver accessor available="+(accessor!=0));
        return accessor;
    }
    public static native long nativeGetFunctionAccessor();
}
