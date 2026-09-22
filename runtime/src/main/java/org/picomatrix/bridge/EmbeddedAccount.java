package org.picomatrix.bridge;

import android.content.Context;
import org.json.JSONObject;

/** Narrow reflection boundary shared with the small host bootstrap. */
public final class EmbeddedAccount {
    public static boolean ready(Context context) throws Exception { return new AccountClient(context).hasGrant(); }
    public static void provision(Context context,String grant) throws Exception { new AccountClient(context).importGrant(new JSONObject(grant)); }
    public static AutoCloseable login(android.app.Activity activity,Runnable signedIn) { return new LoginScreen(activity,signedIn); }
    private EmbeddedAccount() {}
}
