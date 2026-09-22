package org.picomatrix.bridge.installer;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.picomatrix.bridge.installer.InstallCoordinator.*;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class InstallCoordinatorTest {
    private static final Artifact ORIGINAL=new Artifact(Path.of("/research/original.apk"),"a".repeat(64),100);
    private static final Artifact COPY=new Artifact(Path.of("/research/prepared.apk"),"b".repeat(64),110);
    private static Inspection inspection(Dependency d,String profile) { return new Inspection(ORIGINAL,d,"app.example",profile); }
    @Test public void ordinaryAppSkipsAdaptationButStillVerifies() {
        List<Stage> steps=new ArrayList<>();AtomicBoolean checked=new AtomicBoolean();
        InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.NOT_DETECTED,null),
            (i,c)->{throw new AssertionError("must not adapt ordinary app");},
            (i,p)->{assertEquals(ORIGINAL,p.artifact());assertFalse(p.adapted());checked.set(true);},
            p->{assertTrue(checked.get());return InstallResult.INSTALLED;});
        assertEquals(Stage.INSTALLED,flow.run(ORIGINAL,()->false,steps::add).stage());
        assertEquals(List.of(Stage.CHECKING,Stage.VERIFYING,Stage.AWAITING_INSTALL,Stage.INSTALLED),steps);
    }
    @Test public void noInstallAfterBadSignatureInEitherRoute() {
        for(String profile:new String[]{null,"supported-v1"}) {
            InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.MATRIX,profile),
                (i,c)->new Prepared(COPY,true,"app.example.bridge",i.profileId()),
                (i,p)->{throw new SecurityException("signature mismatch");},
                p->{throw new AssertionError("must not install");});
            assertEquals(Stage.FAILED,flow.run(ORIGINAL,()->false,s->{}).stage());
        }
    }
    @Test public void unknownAppUsesGenericAdapterAndCanInstall() {
        AtomicBoolean genericCalled=new AtomicBoolean(),verified=new AtomicBoolean();
        Adapter routing=new AdaptationRouter((i,c)->{
            genericCalled.set(true);return new Prepared(COPY,true,"app.example",null);
        },(i,c)->{throw new AssertionError("no app-specific profile exists");});
        InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.MATRIX,null),routing,
            (i,p)->{assertNull(p.profileId());assertTrue(genericCalled.get());verified.set(true);},
            p->{assertTrue(verified.get());return InstallResult.INSTALLED;});
        assertEquals(Stage.INSTALLED,flow.run(ORIGINAL,()->false,s->{}).stage());
    }
    @Test public void matchedAppUsesOverrideWithoutGenericRetryOnFailure() {
        AtomicBoolean overrideCalled=new AtomicBoolean();
        Adapter routing=new AdaptationRouter((i,c)->{throw new AssertionError("must not ignore known blocker");},
            (i,c)->{overrideCalled.set(true);throw new UnsupportedVersion();});
        InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.MATRIX,"vd-blocked"),routing,
            (i,p)->{throw new AssertionError("not prepared");},p->{throw new AssertionError("not prepared");});
        assertEquals(Stage.FAILED,flow.run(ORIGINAL,()->false,s->{}).stage());
        assertTrue(overrideCalled.get());
    }
    @Test public void failedInspectionIsDifferentFromMissingAppProfile() {
        InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.UNKNOWN,null),
            (i,c)->{throw new AssertionError("input cannot be inspected");},
            (i,p)->{throw new AssertionError();},p->{throw new AssertionError();});
        assertEquals(Stage.FAILED,flow.run(ORIGINAL,()->false,s->{}).stage());
    }
    @Test public void cancellationAfterPreparationStopsBeforeInstallation() {
        AtomicBoolean cancel=new AtomicBoolean();
        InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.MATRIX,"v1"),
            (i,c)->{cancel.set(true);return new Prepared(COPY,true,"app.example.bridge","v1");},
            (i,p)->{throw new AssertionError("cancelled");},p->{throw new AssertionError("cancelled");});
        assertEquals(Stage.CANCELLED,flow.run(ORIGINAL,cancel::get,s->{}).stage());
    }
    @Test public void adaptedCopyRequiresSystemConfirmationAndReportsCancellation() {
        List<Stage> stages=new ArrayList<>();
        InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.MATRIX,"v1"),
            (i,c)->new Prepared(COPY,true,"app.example.bridge","v1"),(i,p)->{},p->InstallResult.USER_CANCELLED);
        assertEquals(Stage.CANCELLED,flow.run(ORIGINAL,()->false,stages::add).stage());
        assertEquals(List.of(Stage.CHECKING,Stage.PREPARING,Stage.VERIFYING,Stage.AWAITING_INSTALL,Stage.CANCELLED),stages);
    }
    @Test public void detachedUiDoesNotMisreportSuccessfulInstall() {
        InstallCoordinator flow=new InstallCoordinator(a->inspection(Dependency.NOT_DETECTED,null),
            (i,c)->{throw new AssertionError();},(i,p)->{},p->InstallResult.INSTALLED);
        assertEquals(Stage.INSTALLED,flow.run(ORIGINAL,()->false,s->{throw new IllegalStateException("screen detached");}).stage());
    }
}
