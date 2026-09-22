package org.picomatrix.bridge.installer;

import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.CancellationException;

/** Host-neutral installation flow; run on the host's worker executor, never its UI thread. */
public final class InstallCoordinator {
    public enum Stage { CHECKING, PREPARING, VERIFYING, AWAITING_INSTALL, INSTALLED, CANCELLED, FAILED }
    public enum Dependency { NOT_DETECTED, MATRIX, UNKNOWN }
    public enum InstallResult { INSTALLED, USER_CANCELLED }
    public record Artifact(Path path, String sha256, long bytes) {
        public Artifact {
            Objects.requireNonNull(path);
            if(!path.isAbsolute() || sha256==null || !sha256.matches("[a-f0-9]{64}") || bytes<=0)
                throw new IllegalArgumentException("invalid artifact identity");
        }
    }
    public record Inspection(Artifact original, Dependency dependency, String packageName, String profileId) {
        public Inspection {
            Objects.requireNonNull(original);Objects.requireNonNull(dependency);Objects.requireNonNull(packageName);
            if(profileId!=null && profileId.isBlank()) profileId=null;
        }
    }
    public record Prepared(Artifact artifact, boolean adapted, String outputPackageName, String profileId) {
        public Prepared { Objects.requireNonNull(artifact);Objects.requireNonNull(outputPackageName); }
    }
    public record Outcome(Stage stage, String code) {}
    public interface Cancellation { boolean isCancelled(); }
    public interface Progress { void changed(Stage stage); }
    public interface Inspector { Inspection inspect(Artifact input) throws Exception; }
    public interface Adapter {
        /** Null profileId uses the generic adapter; a matching app profile selects its override. Never mutate the original. */
        Prepared prepare(Inspection inspection, Cancellation cancellation) throws Exception;
    }
    public interface Verifier {
        /** Recheck bytes/hash/signature, the profile, package identities and embedded runtime. */
        void verify(Inspection original, Prepared candidate) throws Exception;
    }
    public interface Installer {
        /** Complete only after Android reports the result, not after opening its prompt. */
        InstallResult install(Prepared candidate) throws Exception;
    }
    public static final class UnsupportedVersion extends Exception {
        public UnsupportedVersion() { super("An update is needed before this application can be prepared"); }
    }
    private final Inspector inspector;
    private final Adapter adapter;
    private final Verifier verifier;
    private final Installer installer;
    public InstallCoordinator(Inspector inspector,Adapter adapter,Verifier verifier,Installer installer) {
        this.inspector=Objects.requireNonNull(inspector);this.adapter=Objects.requireNonNull(adapter);
        this.verifier=Objects.requireNonNull(verifier);this.installer=Objects.requireNonNull(installer);
    }
    private static void check(Cancellation cancellation) {
        if(cancellation.isCancelled() || Thread.currentThread().isInterrupted()) throw new CancellationException();
    }
    private static void notify(Progress progress,Stage stage) {
        // A detached screen or broken observer must not change an installation result.
        try { progress.changed(stage); } catch(RuntimeException ignored) { }
    }
    public Outcome run(Artifact input,Cancellation cancellation,Progress progress) {
        Objects.requireNonNull(input);Objects.requireNonNull(cancellation);Objects.requireNonNull(progress);
        Stage stage=Stage.CHECKING;
        try {
            check(cancellation);notify(progress,stage);
            Inspection inspection=inspector.inspect(input);
            if(!inspection.original().equals(input)) throw new IllegalStateException("inspection changed input identity");
            check(cancellation);
            if(inspection.dependency()==Dependency.UNKNOWN) throw new UnsupportedVersion();
            Prepared candidate;
            if(inspection.dependency()==Dependency.MATRIX) {
                stage=Stage.PREPARING;notify(progress,stage);
                candidate=adapter.prepare(inspection,cancellation);
                if(!candidate.adapted() || !Objects.equals(inspection.profileId(),candidate.profileId()) || candidate.artifact().path().equals(input.path()))
                    throw new IllegalStateException("adapter violated preparation contract");
            } else candidate=new Prepared(input,false,inspection.packageName(),null);
            check(cancellation);stage=Stage.VERIFYING;notify(progress,stage);
            verifier.verify(inspection,candidate);
            check(cancellation);stage=Stage.AWAITING_INSTALL;notify(progress,stage);check(cancellation);
            // Android owns cancellation once its installer has started; a late host cancellation
            // cannot turn an actual successful installation into a reported cancellation.
            InstallResult result=Objects.requireNonNull(installer.install(candidate));
            stage=result==InstallResult.INSTALLED?Stage.INSTALLED:Stage.CANCELLED;
            notify(progress,stage);return new Outcome(stage,result==InstallResult.INSTALLED?"installed":"installation_cancelled");
        } catch(CancellationException e) {
            notify(progress,Stage.CANCELLED);return new Outcome(Stage.CANCELLED,"cancelled");
        } catch(InterruptedException e) {
            Thread.currentThread().interrupt();notify(progress,Stage.CANCELLED);return new Outcome(Stage.CANCELLED,"cancelled");
        } catch(UnsupportedVersion e) {
            notify(progress,Stage.FAILED);return new Outcome(Stage.FAILED,"application_update_required");
        } catch(Exception e) {
            // Exceptions can contain paths or request payloads. The host gets a stable UI code.
            notify(progress,Stage.FAILED);return new Outcome(Stage.FAILED,stage.name().toLowerCase(java.util.Locale.ROOT)+"_failed");
        }
    }
}
