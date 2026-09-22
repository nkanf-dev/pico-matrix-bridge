package org.picomatrix.bridge.account;

import android.content.Context;
import org.json.JSONObject;

/** Blocking host API. Invoke network methods on a worker thread. */
public final class MatrixAccount {
    private final AccountClient client;
    public MatrixAccount(Context context) {client=new AccountClient(context,null);}
    public void sendCode(String email) throws Exception {client.sendCode(email);}
    public void login(String email,String code) throws Exception {client.login(email,code);}
    /** Returns only account-wide fields, or null when signed out. Never returns game grants. */
    public JSONObject passportSession() throws Exception {return client.passportSession();}
    /** The caller maps legacy token to x_tt_token before the one-time import. */
    public void importPassportSession(JSONObject session) throws Exception {client.importPassportSession(session);}
    public void logout() throws Exception {client.logout();}
    public JSONObject grantFor(String appId,String installedPackage) throws Exception {return client.grantFor(appId,installedPackage);}
}
