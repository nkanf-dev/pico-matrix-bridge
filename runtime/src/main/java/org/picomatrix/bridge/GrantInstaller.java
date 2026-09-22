package org.picomatrix.bridge;

import android.content.Context;
import org.picomatrix.bridge.account.GrantProvisioner;
import org.picomatrix.bridge.account.TargetIdentity;

/** Explicit research fixture; production hosts supply their preparation result's signer. */
final class GrantInstaller {
    static void provision(Context context) throws Exception {
        if(!ResearchTarget.HOST_PACKAGE.equals(context.getPackageName())) throw new SecurityException("Research host required");
        TargetIdentity identity=ResearchTarget.identity();
        GrantProvisioner.provision(context,identity.appId,identity.packageName,TargetIdentity.signerSha256(context,context.getPackageName()));
    }
    private GrantInstaller() {}
}
