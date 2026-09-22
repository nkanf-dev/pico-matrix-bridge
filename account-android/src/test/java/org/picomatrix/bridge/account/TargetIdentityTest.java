package org.picomatrix.bridge.account;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class TargetIdentityTest {
    private JSONObject config() throws Exception {
        return new JSONObject().put("schema",1).put("package","org.example.secondgame").put("appId","different_app")
            .put("account",new JSONObject().put("agwKey","second-profile-key"));
    }
    @Test public void configuredGameControlsAccountIdentity() throws Exception {
        TargetIdentity identity=TargetIdentity.fromConfig(config(),"org.example.secondgame");
        assertEquals("different_app",identity.appId);assertEquals("second-profile-key",identity.agwKey);
    }
    @Test public void configCannotClaimAnotherInstalledPackage() throws Exception {
        assertThrows(SecurityException.class,()->TargetIdentity.fromConfig(config(),"org.example.other"));
    }
    @Test public void unknownSchemaAndMissingSigningConfigFailClosed() throws Exception {
        JSONObject config=config().put("schema",2);
        assertThrows(SecurityException.class,()->TargetIdentity.fromConfig(config,"org.example.secondgame"));
        config.put("schema",1).remove("account");
        assertThrows(org.json.JSONException.class,()->TargetIdentity.fromConfig(config,"org.example.secondgame"));
    }
    @Test public void untrustedIdentityFieldsCannotChangeRequests() {
        assertThrows(IllegalArgumentException.class,()->new TargetIdentity("app&scope=extra","org.example.game","key"));
        assertThrows(IllegalArgumentException.class,()->new TargetIdentity("app","org.example.game/path","key"));
        assertThrows(IllegalArgumentException.class,()->new TargetIdentity("app","org.example.game","key\nheader"));
    }
}
