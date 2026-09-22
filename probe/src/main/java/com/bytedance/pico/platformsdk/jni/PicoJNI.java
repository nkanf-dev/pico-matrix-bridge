package com.bytedance.pico.platformsdk.jni;
/** Original JNI entrypoint signature, used to exercise the existing loader. */
public final class PicoJNI {
    public static native int ppf_InitializeAndroid(String appId,Object activity,long options);
}
