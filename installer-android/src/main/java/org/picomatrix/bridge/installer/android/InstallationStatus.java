package org.picomatrix.bridge.installer.android;

/** Stable UI codes, without protocol payloads or paths. */
public final class InstallationStatus {
    public final String id, stage, packageName, code;
    public InstallationStatus(String id,String stage,String packageName,String code) {
        this.id=id;this.stage=stage;this.packageName=packageName;this.code=code;
    }
    public boolean terminal() {
        return stage.equals("installed") || stage.equals("installed_login_required") || stage.equals("cancelled") || stage.equals("failed");
    }
}
