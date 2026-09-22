package org.picomatrix.bridge.embedded;

import android.content.*;
import android.content.pm.*;
import android.database.Cursor;
import android.net.Uri;
import android.os.*;
import java.security.*;
import java.util.*;
import org.json.JSONObject;

/** One-shot installation handoff, never an account/token read service. */
public final class ProvisioningProvider extends ContentProvider {
    private String challenge;
    private long deadline;
    private int owner;
    @Override public boolean onCreate() { return true; }
    private void verifyCaller(int uid) throws Exception {
        JSONObject config=EmbeddedRuntime.config(getContext());PackageManager pm=getContext().getPackageManager();
        String host=config.getString("provisionerPackage");String[] names=pm.getPackagesForUid(uid);
        if(names==null || names.length!=1 || !host.equals(names[0])) throw new SecurityException("Unknown installer");
        android.content.pm.Signature[] signers=pm.getPackageInfo(host,PackageManager.GET_SIGNING_CERTIFICATES).signingInfo.getApkContentsSigners();
        if(signers.length!=1) throw new SecurityException("Ambiguous installer signer");
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray());StringBuilder hex=new StringBuilder();
        for(byte b:digest) hex.append(String.format(Locale.ROOT,"%02x",b&255));
        if(!hex.toString().equals(config.getString("provisionerSignerSha256"))) throw new SecurityException("Installer signer mismatch");
    }
    @Override public synchronized Bundle call(String method,String arg,Bundle extras) {
        int caller=Binder.getCallingUid();
        try { verifyCaller(caller); } catch(Exception e) { throw new SecurityException("Installer not authorized"); }
        long identity=Binder.clearCallingIdentity();
        try {
            Bundle reply=new Bundle();
            if("begin".equals(method)) {
                byte[] nonce=new byte[32];new SecureRandom().nextBytes(nonce);
                challenge=Base64.getEncoder().encodeToString(nonce);owner=caller;deadline=SystemClock.elapsedRealtime()+60000;
                reply.putString("challenge",challenge);return reply;
            }
            if(!"provision".equals(method) || extras==null || challenge==null || owner!=caller ||
                SystemClock.elapsedRealtime()>deadline || !challenge.equals(extras.getString("challenge")))
                throw new SecurityException("Provisioning challenge unavailable");
            challenge=null;
            String grant=extras.getString("grant","");if(grant.length()>128*1024) throw new SecurityException("Grant too large");
            EmbeddedRuntime.provision(getContext(),grant);
            getContext().getContentResolver().notifyChange(Uri.parse("content://"+getContext().getPackageName()+".matrix.provision"),null);
            reply.putBoolean("accepted",true);return reply;
        } catch(SecurityException e) { throw e; }
        catch(Exception e) { throw new IllegalStateException("Cannot provision application grant"); }
        finally { Binder.restoreCallingIdentity(identity); }
    }
    @Override public Cursor query(Uri u,String[] p,String s,String[] a,String o) { throw new UnsupportedOperationException(); }
    @Override public String getType(Uri u) { return null; }
    @Override public Uri insert(Uri u,ContentValues v) { throw new UnsupportedOperationException(); }
    @Override public int delete(Uri u,String s,String[] a) { throw new UnsupportedOperationException(); }
    @Override public int update(Uri u,ContentValues v,String s,String[] a) { throw new UnsupportedOperationException(); }
}
