package org.picomatrix.bridge.account;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class AccountDataTest {
    private JSONObject passport() throws Exception {
        return new JSONObject().put("uid","1234").put("x_tt_token","passport-test-token").put("email","test@example.com")
            .put("cookies",new JSONObject().put("sessionid","test-cookie"));
    }
    @Test public void passportMappingDiscardsAppTokensAndIsDetached() throws Exception {
        JSONObject old=passport().put("platform",new JSONObject().put("refresh_token","app-only")).put("appId","fixture");
        JSONObject result=AccountData.passport(old);
        assertEquals(4,result.length());assertFalse(result.has("platform"));assertEquals("passport-test-token",result.getString("x_tt_token"));
        old.getJSONObject("cookies").put("sessionid","modified");assertEquals("test-cookie",result.getJSONObject("cookies").getString("sessionid"));
    }
    @Test public void grantProjectionNeverTransfersHostCredentials() throws Exception {
        JSONObject token=passport().put("access_token","app-access").put("refresh_token","app-refresh").put("open_id","open-id")
            .put("expires_in",7200).put("obtained_at",123456);
        JSONObject user=passport().put("account_id","account-id");
        JSONObject grant=AccountData.grant(new TargetIdentity("app_1","org.example.game","fixture-key"),"PUBLIC_KEY_HASH","cert-hash",token,user);
        String encoded=grant.toString();
        assertFalse(encoded.contains("passport-test-token"));assertFalse(encoded.contains("test-cookie"));assertFalse(encoded.contains("test@example.com"));
        assertEquals("app-refresh",grant.getJSONObject("platform").getString("refresh_token"));
        JSONObject target=AccountData.targetState(grant);assertFalse(target.has("cookies"));assertFalse(target.has("uid"));
        assertEquals("org.example.game",target.getString("clientPackage"));
    }
    @Test public void cookieHeaderInjectionIsRejected() throws Exception {
        JSONObject session=passport();session.getJSONObject("cookies").put("sessionid","bad\r\nCookie: injected");
        assertThrows(java.io.IOException.class,()->AccountData.passport(session));
        session.getJSONObject("cookies").put("sessionid","ok").put("bad;name","value");
        assertThrows(java.io.IOException.class,()->AccountData.passport(session));
    }
    @Test public void incompletePassportCannotBeImported() throws Exception {
        JSONObject session=passport();session.remove("x_tt_token");session.remove("cookies");
        assertThrows(java.io.IOException.class,()->AccountData.passport(session));
    }
    @Test public void tokenOnlyAndCookieOnlySessionsRemainCompatible() throws Exception {
        JSONObject tokenOnly=passport();tokenOnly.remove("cookies");
        assertEquals("passport-test-token",AccountData.passport(tokenOnly).getString("x_tt_token"));
        assertEquals(0,AccountData.passport(tokenOnly).getJSONObject("cookies").length());
        JSONObject cookieOnly=passport();cookieOnly.remove("x_tt_token");
        assertEquals("test-cookie",AccountData.passport(cookieOnly).getJSONObject("cookies").getString("sessionid"));
    }
    @Test public void incompletePlatformTokenCannotBeHandedOff() throws Exception {
        assertThrows(java.io.IOException.class,()->AccountData.grant(new TargetIdentity("app","org.example.game","key"),"sig","cert",new JSONObject(),new JSONObject()));
    }
}
