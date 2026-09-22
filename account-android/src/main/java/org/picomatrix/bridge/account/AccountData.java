package org.picomatrix.bridge.account;

import java.io.IOException;
import java.util.*;
import org.json.JSONObject;

/** Explicit projections prevent account-wide credentials entering target grants. */
final class AccountData {
    static JSONObject passport(JSONObject input) throws Exception {
        String uid=input.optString("uid"), token=input.optString("x_tt_token"), email=input.optString("email");
        JSONObject cookies=input.optJSONObject("cookies");if(cookies==null) cookies=new JSONObject();
        if(uid.isEmpty() || (token.isEmpty() && cookies.length()==0) ||
            uid.length()>256 || token.length()>16384 || email.length()>254) throw new IOException("Account session incomplete");
        field(uid);field(token);field(email);
        JSONObject cleanCookies=new JSONObject();
        if(cookies.length()>128) throw new IOException("Account cookie limit");
        for(Iterator<String> keys=cookies.keys();keys.hasNext();) {
            String name=keys.next();Object value=cookies.get(name);
            if(!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}") || !(value instanceof String) ||
                ((String)value).length()>16384 || ((String)value).contains(";")) throw new IOException("Invalid account cookie");
            field((String)value);cleanCookies.put(name,value);
        }
        return new JSONObject().put("uid",uid).put("x_tt_token",token).put("cookies",cleanCookies).put("email",email);
    }
    private static void field(String value) throws IOException {
        if(value.contains("\r") || value.contains("\n") || value.indexOf('\0')>=0) throw new IOException("Invalid account field");
    }
    static void validateToken(JSONObject token) throws Exception {
        if(token.optString("access_token").isEmpty() || token.optString("open_id").isEmpty() || token.optLong("expires_in")<=0)
            throw new IOException("Platform authorization incomplete");
    }
    static JSONObject grant(TargetIdentity target,String signature,String signerSha256,JSONObject token,JSONObject user) throws Exception {
        validateToken(token);
        if(user.optString("account_id").isEmpty()) throw new IOException("Platform user incomplete");
        return new JSONObject().put("schema",1).put("appId",target.appId).put("package",target.packageName)
            .put("clientSignature",signature).put("signerSha256",signerSha256)
            .put("platform",project(token,List.of("access_token","refresh_token","open_id","expires_in","obtained_at")))
            .put("user",project(user,List.of("account_id","nick_name","pico_id","profile","small_image_url","sec_uid","gender","status")));
    }
    static JSONObject targetState(JSONObject grant) throws Exception {
        return new JSONObject().put("platform",grant.getJSONObject("platform")).put("user",grant.getJSONObject("user"))
            .put("clientSignature",grant.getString("clientSignature")).put("signerSha256",grant.getString("signerSha256"))
            .put("clientPackage",grant.getString("package")).put("appId",grant.getString("appId"));
    }
    static JSONObject importGrant(TargetIdentity target,String ownerPackage,String signature,String signerSha256,JSONObject input,long now) throws Exception {
        if(!target.packageName.equals(ownerPackage) || input.getInt("schema")!=1 ||
            !target.appId.equals(input.getString("appId")) || !target.packageName.equals(input.getString("package")) ||
            !signature.equals(input.getString("clientSignature")) || !signerSha256.equals(input.getString("signerSha256")))
            throw new SecurityException("Application grant mismatch");
        JSONObject token=input.getJSONObject("platform"),user=input.getJSONObject("user");validateToken(token);
        if(token.optLong("obtained_at")>now+60 || token.optLong("obtained_at")<=0 ||
            token.getLong("obtained_at")+token.getLong("expires_in")<=now+60 || user.optString("account_id").isEmpty())
            throw new IOException("Application grant expired or incomplete");
        return targetState(grant(target,signature,signerSha256,token,user));
    }
    private static JSONObject project(JSONObject source,List<String> fields) throws Exception {
        JSONObject result=new JSONObject();for(String field:fields) if(source.has(field)) result.put(field,source.get(field));
        return new JSONObject(result.toString());
    }
    private AccountData() {}
}
