package org.picomatrix.bridge.installer.android;

import org.json.JSONObject;
import org.junit.Test;
import static org.junit.Assert.*;

public class InstallationCallbackTest {
    @Test public void collidingGenericPackageCannotReplaceAnotherApplication() throws Exception {
        JSONObject installed=new JSONObject().put("originalPackage","example.first").put("appId","first-id");
        assertTrue(MatrixInstaller.sameAdaptedOrigin(installed,"example.first","first-id"));
        assertFalse(MatrixInstaller.sameAdaptedOrigin(installed,"example.second","first-id"));
        assertFalse(MatrixInstaller.sameAdaptedOrigin(installed,"example.first","other-id"));
        assertFalse(MatrixInstaller.sameAdaptedOrigin(new JSONObject(),"example.first","first-id"));
    }
    @Test public void lostConfirmationIsRequestedAgainInsteadOfBlockingNextInstall() {
        assertEquals(MatrixInstaller.Recovery.RECOMMIT,MatrixInstaller.recoveryAction("awaiting_install",true,true));
        assertEquals(MatrixInstaller.Recovery.INTERRUPTED,MatrixInstaller.recoveryAction("preparing",true,false));
        assertEquals(MatrixInstaller.Recovery.INTERRUPTED,MatrixInstaller.recoveryAction("awaiting_install",false,true));
    }
    @Test public void sameVersionAndSignerCannotCompleteAnotherBuildsReceipt() throws Exception {
        JSONObject receipt=new JSONObject().put("version",42).put("signerSha256","signer").put("apkSha256","original-build");
        assertFalse(MatrixInstaller.matchesIdentity(receipt,42,"signer","different-build"));
        assertTrue(MatrixInstaller.matchesIdentity(receipt,42,"signer","original-build"));
    }
    @Test public void staleOrUnrelatedSystemResultCannotFinishCurrentInstall() throws Exception {
        JSONObject receipt=new JSONObject().put("sessionId",14).put("stage","awaiting_install");
        assertFalse(MatrixInstaller.acceptCallback(receipt,13));
        assertFalse(MatrixInstaller.acceptCallback(receipt,-1));
        assertTrue(MatrixInstaller.acceptCallback(receipt,14));
    }
    @Test public void repeatedSuccessCannotProvisionAgainOrResurrectCancelledInstall() throws Exception {
        for(String stage:new String[]{"preparing","verifying_install","account_setup","installed","installed_login_required","cancelled","failed"})
            assertFalse(MatrixInstaller.acceptCallback(new JSONObject().put("sessionId",14).put("stage",stage),14));
    }
    @Test public void accountFailureIsStillACompletedInstallation() {
        assertTrue(new InstallationStatus("a","installed_login_required","app.example","open_app_to_sign_in").terminal());
        assertFalse(new InstallationStatus("a","awaiting_install","app.example","confirm_installation").terminal());
    }
    @Test public void originalModeBypassesEveryAdaptationRouteIncludingUnknownProfiles() throws Exception {
        assertFalse(MatrixInstaller.shouldAdapt(MatrixInstaller.Mode.ORIGINAL,null));
        for(var route:org.picomatrix.bridge.adapter.AdapterEngine.Route.values())
            assertFalse(MatrixInstaller.shouldAdapt(MatrixInstaller.Mode.ORIGINAL,route));
    }
    @Test public void adaptedModeRequiresSupportedProfileOrGenericDependency() throws Exception {
        assertTrue(MatrixInstaller.shouldAdapt(MatrixInstaller.Mode.ADAPTED,org.picomatrix.bridge.adapter.AdapterEngine.Route.PROFILE));
        for(var route:new org.picomatrix.bridge.adapter.AdapterEngine.Route[]{org.picomatrix.bridge.adapter.AdapterEngine.Route.PASSTHROUGH,org.picomatrix.bridge.adapter.AdapterEngine.Route.ANALYSIS_REQUIRED})
            assertEquals("adaptation_unavailable",assertThrows(java.io.IOException.class,()->MatrixInstaller.shouldAdapt(MatrixInstaller.Mode.ADAPTED,route)).getMessage());
        assertFalse(MatrixInstaller.shouldAdapt(null,org.picomatrix.bridge.adapter.AdapterEngine.Route.PASSTHROUGH));
        assertThrows(java.io.IOException.class,()->MatrixInstaller.shouldAdapt(null,org.picomatrix.bridge.adapter.AdapterEngine.Route.ANALYSIS_REQUIRED));
    }
    @Test public void originalInstallNeverRequestsAnAccountGrantIncludingRecovery() throws Exception {
        assertFalse(MatrixInstaller.needsGrant(new JSONObject().put("mode","original").put("appId","unexpected-stale-id")));
        assertFalse(MatrixInstaller.needsGrant(new JSONObject().put("mode","adapted")));
        assertTrue(MatrixInstaller.needsGrant(new JSONObject().put("mode","adapted").put("appId","real-app-id")));
        assertTrue(MatrixInstaller.needsGrant(new JSONObject().put("appId","legacy-adapted-id")));
    }

    @Test public void adaptedUpdatesRetainTheirSessionWithoutRequestingAnotherGrant() throws Exception {
        JSONObject installed=new JSONObject().put("mode","adapted").put("appId","real-app-id");
        assertTrue(MatrixInstaller.needsGrant(installed.put("operation","install").put("previousUpdate",0)));
        assertFalse(MatrixInstaller.needsGrant(installed.put("operation","update")));
        assertFalse(MatrixInstaller.needsGrant(installed.put("operation","install").put("previousUpdate",1234)));
        installed.remove("operation");
        assertFalse(MatrixInstaller.needsGrant(installed));
    }

    @Test public void successfulReceiptWaitsForWorkerVerificationAndRejectsDuplicateCallbacks() throws Exception {
        JSONObject receipt=new JSONObject().put("id","job").put("sessionId",14).put("stage","verifying_install");
        assertTrue(MatrixInstaller.acceptVerification(receipt));
        assertFalse(MatrixInstaller.acceptCallback(receipt,14));
        assertFalse(new InstallationStatus("job","verifying_install","app.example","verifying_application").terminal());
        for(String stage:new String[]{"awaiting_install","account_setup","installed","installed_login_required","cancelled","failed"})
            assertFalse(MatrixInstaller.acceptVerification(receipt.put("stage",stage)));
        assertFalse(MatrixInstaller.acceptVerification(null));
    }

}
