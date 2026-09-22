package org.picomatrix.bridge.account;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class GrantImportTest {
    private final TargetIdentity target=new TargetIdentity("fixture_app","org.example.game","fixture-key");
    private JSONObject grant() throws Exception {
        return AccountData.grant(target,"pub-key","cert",new JSONObject().put("access_token","access").put("refresh_token","refresh")
            .put("open_id","open-id").put("expires_in",3600).put("obtained_at",1000),new JSONObject().put("account_id","account-id"));
    }
    private JSONObject read(JSONObject input) throws Exception {return AccountData.importGrant(target,target.packageName,"pub-key","cert",input,1100);}
    @Test public void acceptingGrantRetainsOnlyTargetState() throws Exception {
        JSONObject input=grant().put("cookies",new JSONObject().put("sessionid","must-not-cross")).put("uid","host-uid");
        input.getJSONObject("platform").put("x_tt_token","host-token");
        JSONObject state=read(input);
        assertEquals("refresh",state.getJSONObject("platform").getString("refresh_token"));
        assertFalse(state.toString().contains("host-token"));assertFalse(state.has("uid"));assertFalse(state.has("cookies"));
    }
    @Test public void wrongAppPackagePublicKeyAndCertificateAreRejected() throws Exception {
        for(String field:new String[]{"appId","package","clientSignature","signerSha256"}) {
            JSONObject input=grant().put(field,"mismatch");
            assertThrows(SecurityException.class,()->read(input));
        }
        assertThrows(SecurityException.class,()->AccountData.importGrant(target,"org.example.other","pub-key","cert",grant(),1100));
    }
    @Test public void expiredAndFutureGrantsAreRejected() throws Exception {
        JSONObject expired=grant();expired.getJSONObject("platform").put("expires_in",120);
        assertThrows(java.io.IOException.class,()->read(expired));
        JSONObject future=grant();future.getJSONObject("platform").put("obtained_at",1200);
        assertThrows(java.io.IOException.class,()->read(future));
    }
}
