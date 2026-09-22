package com.bytedance.pico.matrix.platform;

import android.content.Context;
import org.picomatrix.bridge.embedded.EmbeddedRuntime;

/** Existing native SDK entry point; delegates to the bundled isolated runtime. */
public final class PlatformSDKDriverLoader {
    public static long load64(Context client,Context runtime,int major,int minor,int patch,int build,int flags) {
        try {
            Class<?> driver=EmbeddedRuntime.load(client).loadClass(PlatformSDKDriverLoader.class.getName());
            return (Long)driver.getMethod("load64",Context.class,Context.class,int.class,int.class,int.class,int.class,int.class)
                .invoke(null,client,client,major,minor,patch,build,flags);
        } catch(Exception e) {
            android.util.Log.e("MatrixBridge","embedded bootstrap failed: "+e.getClass().getSimpleName());
            return 0;
        }
    }
    private PlatformSDKDriverLoader() {}
}
