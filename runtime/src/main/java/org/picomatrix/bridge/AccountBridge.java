package org.picomatrix.bridge;

import android.content.Context;
import android.os.Bundle;
import java.io.IOException;

/** SDK account calls stay in the adapted application's process and UID. */
public final class AccountBridge {
    private static volatile Context client;
    public static synchronized void initialize(Context context) {
        if(client!=null) return;
        Context application=context.getApplicationContext();
        if(application==null) application=context;
        if(!new AccountClient(application).identity().packageName.equals(application.getPackageName()))
            throw new SecurityException("Unexpected SDK client");
        client=application;
        android.util.Log.i("MatrixBridge","embedded account runtime initialized");
    }
    public static Bundle request(int command,byte[] request) throws Exception {
        Context context=client;if(context==null) throw new IOException("Account runtime unavailable");
        Bundle args=new Bundle();args.putInt("command",command);args.putByteArray("request",request);
        return AccountRequests.call(context,args);
    }
    private AccountBridge() {}
}
