package com.bytedance.pico.matrix.server;

import android.content.Context;
import android.util.Log;
import org.picomatrix.bridge.ConfigurationClient;
import org.picomatrix.bridge.AccountBridge;
import android.os.Bundle;
import org.picomatrix.bridge.protocol.MatrixContract;
import org.picomatrix.bridge.protocol.Wire;
import java.util.concurrent.*;

/** JNI contract used by the supplied native SDK. No account success is fabricated. */
public final class ServerBrokerJni {
    private static final ExecutorService requests=new ThreadPoolExecutor(2,2,0L,TimeUnit.SECONDS,new ArrayBlockingQueue<>(16),new ThreadPoolExecutor.AbortPolicy());
    public static long getPackageVersionCode(Context c, String p) {
        try { return c.getPackageManager().getPackageInfo(p,0).getLongVersionCode(); }
        catch(Exception e) { return 0; }
    }
    public static String getPackageVersionName(Context c, String p) {
        try { return c.getPackageManager().getPackageInfo(p,0).versionName; }
        catch(Exception e) { return ""; }
    }
    public static void init(Context context, String appId) {
        AccountBridge.initialize(context);
        try { ConfigurationClient.initialize(context);Log.i("MatrixBridge", "native broker initialized; configuration signer ready"); }
        catch(Exception e) { Log.e("MatrixBridge", "configuration signer unavailable: "+e.getClass().getSimpleName()); }
    }
    public static void initEventLogForBusiness(Context c) { }
    public static byte[] getSignHeaders(boolean get, String appId, String url, byte[] body) {
        try { return ConfigurationClient.sign(get,appId,url,body); }
        catch(Exception e) { return new byte[0]; }
    }
    public static byte[] nativeGetLaunchDetails(Context c) { return new byte[0]; }
    public static void onEvent(String event,String json) { }
    public static void onEventForBusiness(String a,String b,String c,String d) { }
    public static void onLog(int level,String tag,String message) { /* Native payloads can include tokens; do not persist them. */ }
    public static void showPlatformIncompatibleDialog(String description) { Log.w("MatrixBridge", "platform incompatibility reported"); }
    private static void respond(int command,String sequence,long handle,int status,String error,byte[] body) {
        Wire.Builder result=new Wire.Builder().number(MatrixContract.Response.cmd,command).number(MatrixContract.Response.statusCode,status);
        if(sequence!=null) result.string(MatrixContract.Response.sequenceId,sequence);
        if(!error.isEmpty()) result.string(MatrixContract.Response.errorMsg,error);
        if(body!=null) result.bytes(MatrixContract.Response.body,body);
        onResponse(command,sequence,result.build(),handle);
    }
    public static void invokeAsync(int command,String sequence,byte[] request,long handle) {
        Log.i("MatrixBridge", "command="+command+" bytes="+(request==null?0:request.length));
        if(sequence!=null && sequence.length()>256) { respond(command,"",handle,-10001,"Invalid request",null);return; }
        if(request==null || request.length>Wire.MAX_BYTES) { respond(command,sequence,handle,-10001,"Invalid request",null);return; }
        boolean account=command==MatrixContract.CMD_GET_ACCESS_INFO_SILENCE || command==MatrixContract.CMD_GET_OPEN_USER_INFO || command==MatrixContract.CMD_GET_OPEN_ACCESS_TOKEN;
        if(command!=MatrixContract.CMD_CONFIGURATION_GET_CONFIGURATION && !account) { respond(command,sequence,handle,-10001,"Request handler unavailable",null);return; }
        byte[] owned=request.clone();
        try {
            requests.execute(()->{
                byte[] body;
                try {
                    if(account) {
                        Bundle result=AccountBridge.request(command,owned);
                        int status=result.getInt("status",-10001);
                        Log.i("MatrixBridge","account command="+command+" status="+status);
                        respond(command,sequence,handle,status,result.getString("error",""),result.getByteArray("body"));return;
                    }
                    body=ConfigurationClient.fetch(owned);
                }
                catch(Exception e) {
                    Log.w("MatrixBridge","request failed: "+e.getClass().getSimpleName());
                    respond(command,sequence,handle,-10001,"Request unavailable",null);return;
                }
                Log.i("MatrixBridge","configuration received");
                respond(command,sequence,handle,0,"",body);
            });
        } catch(RejectedExecutionException e) { respond(command,sequence,handle,-10001,"Request queue full",null); }
    }
    public static native void onNotification(int command,byte[] data);
    public static native void onReportTtNetParams(String params);
    public static native void onResponse(int command,String sequence,byte[] response,long handle);
}
