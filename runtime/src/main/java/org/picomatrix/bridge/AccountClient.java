package org.picomatrix.bridge;

import android.content.Context;
import org.picomatrix.bridge.account.TargetIdentity;

/** Runtime adapter; the account protocol and storage are shared with installer hosts. */
final class AccountClient extends org.picomatrix.bridge.account.AccountClient {
    AccountClient(Context context) {super(context,identityFor(context));}
    private static TargetIdentity identityFor(Context context) {
        if(ResearchTarget.HOST_PACKAGE.equals(context.getPackageName())) return ResearchTarget.identity();
        try {return TargetIdentity.embedded(context);}
        catch(Exception e) {throw new IllegalStateException("Embedded account configuration unavailable",e);}
    }
}
