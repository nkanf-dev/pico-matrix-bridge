package com.bytedance.pico.matrix.server;

import android.content.Context;
import org.picomatrix.bridge.embedded.EmbeddedRuntime;

/** Native AppThread resolves this contract through the target package loader. */
public final class ServerBrokerJni {
    public static long getPackageVersionCode(Context c,String p) {return (Long)EmbeddedRuntime.broker("getPackageVersionCode",new Class<?>[]{Context.class,String.class},c,p);}
    public static String getPackageVersionName(Context c,String p) {return (String)EmbeddedRuntime.broker("getPackageVersionName",new Class<?>[]{Context.class,String.class},c,p);}
    public static void init(Context c,String app) {EmbeddedRuntime.broker("init",new Class<?>[]{Context.class,String.class},c,app);}
    public static void initEventLogForBusiness(Context c) {EmbeddedRuntime.broker("initEventLogForBusiness",new Class<?>[]{Context.class},c);}
    public static byte[] getSignHeaders(boolean get,String app,String url,byte[] body) {return (byte[])EmbeddedRuntime.broker("getSignHeaders",new Class<?>[]{boolean.class,String.class,String.class,byte[].class},get,app,url,body);}
    public static byte[] nativeGetLaunchDetails(Context c) {return (byte[])EmbeddedRuntime.broker("nativeGetLaunchDetails",new Class<?>[]{Context.class},c);}
    public static void onEvent(String event,String json) {EmbeddedRuntime.broker("onEvent",new Class<?>[]{String.class,String.class},event,json);}
    public static void onEventForBusiness(String a,String b,String c,String d) {EmbeddedRuntime.broker("onEventForBusiness",new Class<?>[]{String.class,String.class,String.class,String.class},a,b,c,d);}
    public static void onLog(int level,String tag,String message) { /* Never persist native account payloads. */ }
    public static void showPlatformIncompatibleDialog(String description) {EmbeddedRuntime.broker("showPlatformIncompatibleDialog",new Class<?>[]{String.class},description);}
    public static void invokeAsync(int command,String sequence,byte[] request,long handle) {EmbeddedRuntime.broker("invokeAsync",new Class<?>[]{int.class,String.class,byte[].class,long.class},command,sequence,request,handle);}
    public static void onNotification(int command,byte[] data) {EmbeddedRuntime.broker("onNotification",new Class<?>[]{int.class,byte[].class},command,data);}
    public static void onReportTtNetParams(String params) {EmbeddedRuntime.broker("onReportTtNetParams",new Class<?>[]{String.class},params);}
    public static void onResponse(int command,String sequence,byte[] response,long handle) {EmbeddedRuntime.broker("onResponse",new Class<?>[]{int.class,String.class,byte[].class,long.class},command,sequence,response,handle);}
    private ServerBrokerJni() {}
}
