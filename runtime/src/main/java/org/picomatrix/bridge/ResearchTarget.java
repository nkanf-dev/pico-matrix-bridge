package org.picomatrix.bridge;

import org.picomatrix.bridge.account.TargetIdentity;

/** Explicit legacy VD fixture used only by the standalone research companion UI. */
final class ResearchTarget {
    static final String HOST_PACKAGE="org.picomatrix.bridge";
    static TargetIdentity identity() {
        return new TargetIdentity("3cd8ad26e891e5c2ac8beeba35588f8f","org.picomatrix.bridge.vd","N6HCMSN3Gy45UEZNBo72hxiEnk5BMvKM");
    }
    private ResearchTarget() {}
}
