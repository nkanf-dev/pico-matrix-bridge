package org.picomatrix.bridge;

import android.app.Instrumentation;
import android.os.Bundle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.io.File;
import org.json.JSONObject;
import org.picomatrix.bridge.account.SessionStore;

/** Explicit local research actions; only included in the separately signed test APK. */
public final class AccountFlowInstrumentation extends Instrumentation {
    private Bundle args;
    @Override public void onCreate(Bundle arguments) { args=arguments;start(); }
    @Override public void onStart() {
        Bundle result=new Bundle();
        try {
            AccountClient client=new AccountClient(getTargetContext());
            String action=args.getString("action","");
            switch(action) {
                case "send-code": client.sendCode(args.getString("email",""));break;
                case "login": client.login(args.getString("email",""),args.getString("code",""));break;
                case "authorize": client.authorize();break;
                case "provision": GrantInstaller.provision(getTargetContext());break;
                case "state": {
                    JSONObject state=client.access();
                    result.putBoolean("platformTokenPresent",!state.getJSONObject("platform").optString("access_token").isEmpty());
                    result.putBoolean("userPresent",!state.getJSONObject("user").optString("account_id").isEmpty());
                    break;
                }
                case "storage-test": {
                    SessionStore store=SessionStore.get(getTargetContext());
                    if(store.read()!=null) throw new IllegalStateException("Storage test requires an empty account");
                    long epoch=store.generation();String marker="test-session-never-plaintext-7f029d";
                    store.save(epoch,new JSONObject().put("marker",marker));
                    if(!marker.equals(store.read().getString("marker"))) throw new AssertionError("Encrypted round trip failed");
                    byte[] disk=Files.readAllBytes(new File(getTargetContext().getNoBackupFilesDir(),"account.sealed").toPath());
                    if(new String(disk,StandardCharsets.ISO_8859_1).contains(marker)) throw new AssertionError("Plaintext account found");
                    store.clear();boolean rejected=false;
                    try {store.save(epoch,new JSONObject().put("marker",marker));}catch(AccountClient.Failure expected){rejected=true;}
                    if(!rejected || store.read()!=null) throw new AssertionError("Logout did not invalidate in-flight work");
                    result.putBoolean("encryptedRoundTrip",true);result.putBoolean("staleCommitRejected",true);break;
                }
                default: throw new IllegalArgumentException("Unknown research action");
            }
            result.putString("action",action);result.putBoolean("success",true);finish(-1,result);
        } catch(Throwable e) {
            result.putBoolean("success",false);result.putString("failure",e.getClass().getSimpleName());
            String reason=e.getMessage();
            if(reason!=null && (reason.matches("PICO HTTP [0-9]{3}") || reason.equals("Account session incomplete") || reason.equals("Platform authorization incomplete") || reason.equals("Platform user incomplete"))) result.putString("reason",reason);
            if(e instanceof AccountClient.Failure f) result.putInt("status",f.code);
            finish(1,result);
        }
    }
}
