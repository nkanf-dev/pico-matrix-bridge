package org.picomatrix.bridge.installer.android;

/** Stable UI codes, without protocol payloads or paths. */
public final class InstallationStatus {
    public final String id, stage, packageName, code;
    public final Integer installerStatus, installerLegacyStatus;
    public InstallationStatus(String id,String stage,String packageName,String code) {
        this(id,stage,packageName,code,null,null);
    }
    public InstallationStatus(String id,String stage,String packageName,String code,Integer installerStatus,Integer installerLegacyStatus) {
        this.id=id;this.stage=stage;this.packageName=packageName;this.code=code;
        this.installerStatus=installerStatus;this.installerLegacyStatus=installerLegacyStatus;
    }
    public boolean terminal() {
        return stage.equals("installed") || stage.equals("installed_login_required") || stage.equals("cancelled") || stage.equals("failed");
    }
}
