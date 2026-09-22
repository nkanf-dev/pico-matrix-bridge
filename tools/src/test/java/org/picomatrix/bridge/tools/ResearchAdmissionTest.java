package org.picomatrix.bridge.tools;
import org.picomatrix.bridge.adapter.*;

import static org.junit.Assert.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.json.*;
import org.junit.Test;

public class ResearchAdmissionTest {
    private JSONObject inspection() {
        return new JSONObject().put("source",new JSONObject().put("sha256","a".repeat(64)))
            .put("manifest",new JSONObject().put("package","example.app"));
    }
    private JSONObject profile() {
        return new JSONObject().put("id","example-1").put("status","research")
            .put("package","example.app").put("inputSha256","a".repeat(64));
    }
    @Test public void dependencyDetectionDoesNotAdmitUnreviewedApp() {
        var report=ResearchAdapter.admission(inspection(),profile());
        assertFalse(report.getBoolean("adaptationAllowed"));
        assertEquals("STATIC_REVIEW_REQUIRED",report.getJSONArray("blockers").getJSONObject(0).getString("code"));
        assertThrows(IllegalArgumentException.class,()->ResearchAdapter.requireAdmission(report));
    }
    @Test public void knownSignerBlockRemainsBlockedEvenWithReadyLabel() {
        for(String status:new String[]{"blocked","ready-for-device-validation"}) {
            var profile=profile().put("staticAssessment",new JSONObject().put("status",status)
                .put("blockers",new JSONArray().put(new JSONObject().put("code","APP_SIGNER_PINNING"))));
            var report=ResearchAdapter.admission(inspection(),profile);
            assertFalse(report.getBoolean("adaptationAllowed"));
            assertThrows(IllegalArgumentException.class,()->ResearchAdapter.requireAdmission(report));
        }
    }
    @Test public void reviewCanPermitExperimentWithoutClaimingCompatibility() {
        var profile=profile().put("staticAssessment",new JSONObject()
            .put("status","ready-for-device-validation").put("blockers",new JSONArray()));
        var report=ResearchAdapter.admission(inspection(),profile);
        ResearchAdapter.requireAdmission(report);
        assertFalse(report.getBoolean("functionalValidation"));
    }
    @Test public void assessmentCannotCarryAcrossInputChanges() {
        assertThrows(IllegalArgumentException.class,()->ResearchAdapter.admission(inspection(),profile().put("inputSha256","b".repeat(64))));
        assertThrows(IllegalArgumentException.class,()->ResearchAdapter.admission(inspection(),profile().put("package","another.app")));
    }
    @Test public void routeOnlyChangesFullPackageLiteralAndRetainsInput() {
        byte[] bytes=("\u007fELFcom.bytedance.pico.matrix\0com.bytedance.pico.matrix.platform.PlatformSDKDriverLoader\0")
            .getBytes(StandardCharsets.US_ASCII);
        byte[] original=bytes.clone(),routed=ResearchAdapter.route(bytes,1);
        assertArrayEquals(original,bytes);
        assertEquals(bytes.length,routed.length);
        assertTrue(Main.contains(routed,"org.picomatrix.bridge\0".getBytes(StandardCharsets.US_ASCII)));
        assertTrue(Main.contains(routed,"com.bytedance.pico.matrix.platform.PlatformSDKDriverLoader\0".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(Arrays.equals(bytes,routed));
        assertThrows(IllegalArgumentException.class,()->ResearchAdapter.route(bytes,2));
    }
}
