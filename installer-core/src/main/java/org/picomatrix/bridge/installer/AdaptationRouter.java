package org.picomatrix.bridge.installer;

import java.util.Objects;
import static org.picomatrix.bridge.installer.InstallCoordinator.*;

/** App profiles override the generic path; they are not an application allowlist. */
public final class AdaptationRouter implements Adapter {
    private final Adapter generic;
    private final Adapter application;

    public AdaptationRouter(Adapter generic,Adapter application) {
        this.generic=Objects.requireNonNull(generic);
        this.application=Objects.requireNonNull(application);
    }

    @Override public Prepared prepare(Inspection inspection,Cancellation cancellation) throws Exception {
        // A failed matched profile is not retried through generic handling: it may carry
        // a known incompatibility which generic handling cannot diagnose or fix.
        return (inspection.profileId()==null?generic:application).prepare(inspection,cancellation);
    }
}
