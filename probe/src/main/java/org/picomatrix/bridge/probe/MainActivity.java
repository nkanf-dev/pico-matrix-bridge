package org.picomatrix.bridge.probe;
import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;
import com.bytedance.pico.platformsdk.jni.PicoJNI;

public final class MainActivity extends Activity {
    @Override public void onCreate(Bundle b) {
        super.onCreate(b); TextView text=new TextView(this);setContentView(text);
        new Thread(()->{
            String result;
            try {
                if(getIntent().getBooleanExtra("bridge_ipc_only",false)) {
                    android.content.pm.ProviderInfo p=getPackageManager().resolveContentProvider("org.picomatrix.bridge.account",0);
                    Log.i("MatrixBridgeProbe","provider resolved="+(p!=null));
                    try {
                        getContentResolver().call(android.net.Uri.parse("content://org.picomatrix.bridge.account"),"request",null,new Bundle());
                        Log.i("MatrixBridgeProbe","unexpected unregistered caller accepted");
                    } catch(SecurityException denied) {Log.i("MatrixBridgeProbe","unregistered caller rejected");}
                    catch(IllegalArgumentException missing) {Log.i("MatrixBridgeProbe","provider unavailable");}
                    return;
                }
                System.loadLibrary("pxrplatformloader4j");
                String appId=getIntent().getStringExtra("sdk_app_id");
                if(appId==null || !appId.matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException("Supply the app ID observed in the supplied client manifest");
                int status=PicoJNI.ppf_InitializeAndroid(appId,this,0);
                result="SDK initialization result="+status;
            } catch(Throwable t) { result="Bootstrap failed: "+t.getClass().getName()+": "+t.getMessage(); }
            Log.i("MatrixBridgeProbe",result); String value=result;runOnUiThread(()->text.setText(value));
        },"matrix-probe").start();
    }
}
