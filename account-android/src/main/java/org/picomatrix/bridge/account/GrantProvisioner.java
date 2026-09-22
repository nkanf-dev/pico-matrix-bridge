package org.picomatrix.bridge.account;

import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.os.Bundle;
import java.util.Locale;
import org.json.JSONObject;

/** Authenticated one-use installation handoff. No Passport data crosses Binder. */
public final class GrantProvisioner {
    public static void provision(Context context,String appId,String packageName,String expectedSignerSha256) throws Exception {
        provision(context,appId,packageName,expectedSignerSha256,true);
    }
    /** launchTarget=false is for an already running receiver; no retry loop is performed. */
    public static void provision(Context context,String appId,String packageName,String expectedSignerSha256,boolean launchTarget) throws Exception {
        if(expectedSignerSha256==null || !expectedSignerSha256.matches("[a-fA-F0-9]{64}"))
            throw new IllegalArgumentException("Invalid expected application signer");
        String expected=expectedSignerSha256.toLowerCase(Locale.ROOT);
        verifyReceiver(context,packageName,expected);
        SessionStore store=SessionStore.get(context);long epoch=store.generation();
        JSONObject grant=new MatrixAccount(context).grantFor(appId,packageName);
        verifyReceiver(context,packageName,expected);
        if(!expected.equals(grant.getString("signerSha256"))) throw new SecurityException("Grant receiver changed");
        if(launchTarget) {
            Intent launch=context.getPackageManager().getLaunchIntentForPackage(packageName);
            if(launch==null) throw new IllegalStateException("Adapted application has no launch activity");
            synchronized(store) {store.check(epoch);context.startActivity(launch.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));}
        }
        Uri uri=Uri.parse("content://"+packageName+".matrix.provision");
        try(ContentProviderClient provider=context.getContentResolver().acquireUnstableContentProviderClient(uri)) {
            if(provider==null) throw new IllegalStateException("Application not ready for account handoff");
            Bundle challenge=provider.call("begin",null,null);
            if(challenge==null || challenge.getString("challenge")==null) throw new IllegalStateException("No handoff challenge");
            Bundle args=new Bundle();args.putString("challenge",challenge.getString("challenge"));args.putString("grant",grant.toString());
            synchronized(store) {
                // Logout linearizes before or after this call, never between its
                // final generation check and sending the grant.
                store.check(epoch);verifyReceiver(context,packageName,expected);
                Bundle reply=provider.call("provision",null,args);
                if(reply==null || !reply.getBoolean("accepted")) throw new IllegalStateException("Account handoff failed");
            }
        }
    }
    private static void verifyReceiver(Context context,String packageName,String expected) throws Exception {
        PackageManager pm=context.getPackageManager();ProviderInfo receiver=pm.resolveContentProvider(packageName+".matrix.provision",0);
        if(receiver==null || !packageName.equals(receiver.packageName) || !receiver.exported ||
            !expected.equals(TargetIdentity.signerSha256(context,packageName))) throw new SecurityException("Unexpected grant receiver");
        String[] packages=pm.getPackagesForUid(receiver.applicationInfo.uid);
        if(packages==null || packages.length!=1 || !packageName.equals(packages[0])) throw new SecurityException("Ambiguous grant receiver UID");
    }
    private GrantProvisioner() {}
}
