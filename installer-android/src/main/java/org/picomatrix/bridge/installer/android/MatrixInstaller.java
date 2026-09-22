package org.picomatrix.bridge.installer.android;

import android.app.PendingIntent;
import android.content.*;
import android.content.pm.*;
import android.net.Uri;
import android.os.StatFs;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipFile;
import org.json.JSONObject;
import org.picomatrix.bridge.account.GrantProvisioner;
import org.picomatrix.bridge.adapter.AdapterEngine;
import java.io.*;
import java.security.KeyStore;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

/** Runs on a worker; installation completion is durable and independent of an Activity. */
public final class MatrixInstaller {
    static final ExecutorService EXECUTOR=Executors.newSingleThreadExecutor();
    private static final AtomicBoolean PREPARING=new AtomicBoolean();
    private static final CopyOnWriteArrayList<Listener> LISTENERS=new CopyOnWriteArrayList<>();
    public enum Mode { ORIGINAL, ADAPTED }
    public interface Listener { void changed(InstallationStatus status); }
    private final Context context;
    private final InstallationJournal journal;
    public MatrixInstaller(Context context) {this.context=context.getApplicationContext();journal=new InstallationJournal(this.context);}
    public AutoCloseable observe(Listener listener) {LISTENERS.add(listener);return ()->LISTENERS.remove(listener);}
    private static void emit(InstallationStatus status) {for(Listener l:LISTENERS) try {l.changed(status);} catch(RuntimeException ignored) {}}
    private void stage(JSONObject record,String stage,String code) throws Exception {
        record.put("stage",stage).put("code",code);journal.save(record);emit(InstallationJournal.status(record));
    }
    private InstallationStatus progress(String id,String stage,String pkg,String code) {
        InstallationStatus status=new InstallationStatus(id,stage,pkg,code);emit(status);return status;
    }
    public InstallationStatus prepareAndInstall(File original,File bundle) throws Exception {
        return prepareAndInstallInternal(original,bundle,null);
    }
    public InstallationStatus prepareAndInstall(File original,File bundle,Mode mode) throws Exception {
        return prepareAndInstallInternal(original,bundle,Objects.requireNonNull(mode,"mode"));
    }
    static boolean shouldAdapt(Mode mode,AdapterEngine.Route route) throws IOException {
        if(mode==Mode.ORIGINAL)return false;
        if(route==AdapterEngine.Route.PROFILE || route==AdapterEngine.Route.GENERIC)return true;
        if(mode==Mode.ADAPTED)throw new IOException("adaptation_unavailable");
        if(route==AdapterEngine.Route.ANALYSIS_REQUIRED)throw new IOException("application_update_required");
        if(route==AdapterEngine.Route.PASSTHROUGH)return false;
        throw new IOException("preparation_failed");
    }
    static boolean needsGrant(JSONObject record) {
        return !"original".equals(record.optString("mode")) && !"update".equals(record.optString("operation"))
            && record.optLong("previousUpdate",0)==0 && !record.optString("appId").isEmpty();
    }
    private InstallationStatus prepareAndInstallInternal(File original,File bundle,Mode mode) throws Exception {
        if(!PREPARING.compareAndSet(false,true)) throw new IllegalStateException("installation_busy");
        String id=UUID.randomUUID().toString();File work=null;
        try {
            for(JSONObject r:journal.read()) if(!InstallationJournal.status(r).terminal()) throw new IllegalStateException("installation_busy");
            progress(id,"checking","","checking_application");
            if(!original.isFile() || original.length()==0) throw new IOException("download_unavailable");
            String originalHash=LocalSigner.hash(original);
            String originalSigner=LocalSigner.verify(original);
            if(!originalHash.equals(LocalSigner.hash(original))) throw new SecurityException("preparation_changed");
            AdapterEngine.Inspection inspection=null;
            if(mode!=Mode.ORIGINAL) {
                inspection=AdapterEngine.inspect(original.toPath(),bundle.toPath());
                if(!originalHash.equals(inspection.inputSha256)) throw new SecurityException("preparation_changed");
            }
            boolean adapted=shouldAdapt(mode,inspection==null?null:inspection.route);
            File candidate=original;String appId="",profile="",signer=originalSigner;
            if(adapted) {
                progress(id,"preparing",inspection.packageName,"preparing_application");
                if(new StatFs(context.getCacheDir().getPath()).getAvailableBytes()<original.length()*2+256L*1024*1024)
                    throw new IOException("not_enough_storage");
                work=new File(context.getCacheDir(),"matrix-preparation/"+id);
                if(!work.mkdirs()) throw new IOException("preparation_unavailable");
                KeyStore.PrivateKeyEntry key=LocalSigner.identity();
                File unsigned=new File(work,"unsigned.apk"),signed=new File(work,"prepared.apk");
                AdapterEngine.Result prepared=AdapterEngine.prepare(original.toPath(),bundle.toPath(),unsigned.toPath(),
                    key.getCertificate().getEncoded(),context.getPackageName(),LocalSigner.installedSigner(context,context.getPackageName()));
                if(!originalHash.equals(prepared.inputSha256)) throw new SecurityException("preparation_changed");
                if(!prepared.requiresSigning || !prepared.output.toFile().getCanonicalFile().equals(unsigned.getCanonicalFile()))
                    throw new SecurityException("preparation_contract_failed");
                progress(id,"verifying",prepared.packageName,"verifying_application");
                if(!LocalSigner.hash(unsigned).equals(prepared.outputSha256)) throw new SecurityException("preparation_changed");
                LocalSigner.sign(unsigned,signed,key);unsigned.delete();
                signer=LocalSigner.hash(key.getCertificate().getEncoded());
                if(!signer.equals(prepared.targetSignerSha256)) throw new SecurityException("preparation_signer_mismatch");
                candidate=signed;appId=prepared.appId;profile=prepared.profileId;
            }
            PackageInfo info=context.getPackageManager().getPackageArchiveInfo(candidate.getPath(),0);
            if(info==null) throw new IOException("invalid_application");
            long previousUpdate=0;boolean updating=false;
            try {
                PackageInfo installed=context.getPackageManager().getPackageInfo(info.packageName,0);
                previousUpdate=installed.lastUpdateTime;
                if(!signer.equals(LocalSigner.installedSigner(context,info.packageName)))
                    throw new SecurityException("existing_signature_conflict");
                if("generic-native-matrix-v1".equals(profile) && !sameGenericOrigin(
                        embeddedConfig(new File(installed.applicationInfo.sourceDir)),inspection.packageName,appId))
                    throw new SecurityException("existing_signature_conflict");
                if(installed.getLongVersionCode()>info.getLongVersionCode()) throw new SecurityException("application_downgrade");
                updating=true;
            } catch(PackageManager.NameNotFoundException ignored) {}
            String candidateHash=LocalSigner.hash(candidate);
            if(!adapted && !originalHash.equals(candidateHash)) throw new SecurityException("preparation_changed");
            if(!signer.equals(LocalSigner.verify(candidate)) || !candidateHash.equals(LocalSigner.hash(candidate)))
                throw new SecurityException("preparation_changed");
            JSONObject record=new JSONObject().put("id",id).put("package",info.packageName).put("version",info.getLongVersionCode())
                .put("signerSha256",signer).put("apkSha256",candidateHash).put("appId",appId==null?"":appId)
                .put("profile",profile==null?"":profile).put("mode",adapted?"adapted":"original").put("operation",updating?"update":"install").put("previousUpdate",previousUpdate)
                .put("createdAt",System.currentTimeMillis()).put("stage","preparing").put("code","preparing_installation");
            PackageInstaller installer=context.getPackageManager().getPackageInstaller();
            PackageInstaller.SessionParams params=new PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL);
            params.setAppPackageName(info.packageName);params.setSize(candidate.length());
            int sessionId=installer.createSession(params);record.put("sessionId",sessionId);
            try(PackageInstaller.Session session=installer.openSession(sessionId)) {
                journal.save(record);
                java.security.MessageDigest stagedHash=java.security.MessageDigest.getInstance("SHA-256");
                try(InputStream input=new FileInputStream(candidate);OutputStream output=session.openWrite("base.apk",0,candidate.length())) {
                    byte[] buffer=new byte[65536];int n;while((n=input.read(buffer))!=-1) {output.write(buffer,0,n);stagedHash.update(buffer,0,n);}session.fsync(output);
                }
                if(!candidateHash.equals(LocalSigner.hex(stagedHash.digest()))) throw new SecurityException("preparation_changed");
                stage(record,"awaiting_install","confirm_installation");
                session.commit(callback(record).getIntentSender());
            } catch(Exception e) {
                try {installer.abandonSession(sessionId);} catch(RuntimeException ignored) {}
                stage(record,"failed","installation_failed");throw e;
            }
            return InstallationJournal.status(record);
        } catch(Exception e) {
            String code=knownCode(e.getMessage());progress(id,"failed","",code);throw new IOException(code);
        } finally {
            // PackageInstaller owns its staged bytes after fsync/commit. Keep the original download.
            if(work!=null) removeGenerated(work);PREPARING.set(false);
        }
    }
    private static String knownCode(String code) {
        if(code!=null && Set.of("installation_busy","download_unavailable","application_update_required","not_enough_storage",
            "existing_signature_conflict","application_downgrade","adaptation_unavailable").contains(code)) return code;
        return "preparation_failed";
    }
    private PendingIntent callback(JSONObject record) throws Exception {
        Intent intent=new Intent(context,InstallResultReceiver.class).setAction(context.getPackageName()+".MATRIX_INSTALL_RESULT")
            .setData(Uri.parse("matrix-install://result/"+record.getString("id")));
        return PendingIntent.getBroadcast(context,record.getInt("sessionId"),intent,PendingIntent.FLAG_UPDATE_CURRENT|PendingIntent.FLAG_MUTABLE);
    }
    void receive(Intent intent) {
        synchronized(InstallationJournal.LOCK) {
        try {
            Uri data=intent.getData();
            if(data==null || !"matrix-install".equals(data.getScheme()) || !"result".equals(data.getHost())) return;
            JSONObject record=journal.get(data.getLastPathSegment());
            if(record==null || !acceptCallback(record,intent.getIntExtra(PackageInstaller.EXTRA_SESSION_ID,-1))) return;
            int status=intent.getIntExtra(PackageInstaller.EXTRA_STATUS,PackageInstaller.STATUS_FAILURE);
            if(status==PackageInstaller.STATUS_PENDING_USER_ACTION) {
                @SuppressWarnings("deprecation") Intent confirmation=intent.getParcelableExtra(Intent.EXTRA_INTENT);
                if(confirmation==null) {stage(record,"failed","installation_failed");return;}
                stage(record,"awaiting_install","confirm_installation");
                context.startActivity(confirmation.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK));return;
            }
            if(status==PackageInstaller.STATUS_SUCCESS) {
                stage(record,"verifying_install","verifying_application");
                String id=record.getString("id");
                EXECUTOR.execute(()->completeVerification(id));
            } else if(status==PackageInstaller.STATUS_FAILURE_ABORTED) stage(record,"cancelled","installation_cancelled");
            else stage(record,"failed","installation_failed");
        } catch(Exception ignored) {emit(new InstallationStatus("","failed","","installation_status_unavailable"));}
        }
    }
    private void completeVerification(String id) {
        JSONObject record=null;
        try {
            record=journal.get(id);
            if(!acceptVerification(record))return;
            if(!installedMatches(record,false)) {stage(record,"failed","installed_identity_mismatch");return;}
            finishAccount(record);
        } catch(Exception ignored) {
            try {
                if(record!=null)stage(record,"failed","installation_status_unavailable");
                else emit(new InstallationStatus(id,"failed","","installation_status_unavailable"));
            } catch(Exception unavailable) {emit(new InstallationStatus(id,"failed","","installation_status_unavailable"));}
        }
    }
    static boolean acceptVerification(JSONObject record) {
        return record!=null && "verifying_install".equals(record.optString("stage"));
    }
    static boolean acceptCallback(JSONObject record,int sessionId) {
        return sessionId==record.optInt("sessionId",-2) && "awaiting_install".equals(record.optString("stage"));
    }
    private boolean installedMatches(JSONObject record,boolean requireUpdate) throws Exception {
        try {
            PackageInfo installed=context.getPackageManager().getPackageInfo(record.getString("package"),0);
            return matchesIdentity(record,installed.getLongVersionCode(),
                LocalSigner.installedSigner(context,installed.packageName),
                LocalSigner.hash(new File(installed.applicationInfo.sourceDir))) &&
                (!requireUpdate || installed.lastUpdateTime>record.optLong("previousUpdate"));
        } catch(PackageManager.NameNotFoundException e) {return false;}
    }
    static boolean matchesIdentity(JSONObject record,long version,String signer,String apkHash) throws Exception {
        return version==record.getLong("version") && signer.equals(record.getString("signerSha256")) &&
            apkHash.equals(record.getString("apkSha256"));
    }
    static boolean sameGenericOrigin(JSONObject config,String originalPackage,String appId) {
        return originalPackage.equals(config.optString("originalPackage")) && appId.equals(config.optString("appId"));
    }
    private static JSONObject embeddedConfig(File apk) throws Exception {
        try(ZipFile zip=new ZipFile(apk)) {
            var entry=zip.getEntry("assets/matrix-embedded.json");
            if(entry==null) return new JSONObject();
            try(InputStream input=zip.getInputStream(entry);ByteArrayOutputStream output=new ByteArrayOutputStream()) {
                byte[] bytes=new byte[4096];int count;
                while((count=input.read(bytes))!=-1) {
                    if(output.size()+count>65536) throw new SecurityException("existing_signature_conflict");
                    output.write(bytes,0,count);
                }
                return new JSONObject(new String(output.toByteArray(),StandardCharsets.UTF_8));
            }
        }
    }
    enum Recovery { INTERRUPTED, RECOMMIT }
    static Recovery recoveryAction(String stage,boolean owned,boolean sealed) {
        return owned && sealed && "awaiting_install".equals(stage) ? Recovery.RECOMMIT : Recovery.INTERRUPTED;
    }
    private void finishAccount(JSONObject record) throws Exception {
        if(!needsGrant(record)) {stage(record,"installed","installed");return;}
        stage(record,"account_setup","connecting_account");
        try {
            GrantProvisioner.provision(context,record.getString("appId"),record.getString("package"),record.getString("signerSha256"));
            stage(record,"installed","installed");
        } catch(Exception ignored) {
            // Installation succeeded. The target's normal login remains available.
            stage(record,"installed_login_required","open_app_to_sign_in");
        }
    }
    public void reconcile() {
        EXECUTOR.execute(()->{
            if(!PREPARING.compareAndSet(false,true)) return;
            try {
                for(JSONObject record:journal.read()) {
                    InstallationStatus status=InstallationJournal.status(record);
                    if(status.terminal()) continue;
                    if(acceptVerification(record)) {completeVerification(record.getString("id"));continue;}
                    boolean matches=installedMatches(record,true);
                    synchronized(InstallationJournal.LOCK) {
                        JSONObject current=journal.get(record.getString("id"));
                        if(current==null || !status.stage.equals(current.optString("stage")))continue;
                        if(matches) {
                            stage(record,"verifying_install","verifying_application");
                        } else {
                            PackageInstaller.SessionInfo session=context.getPackageManager().getPackageInstaller().getSessionInfo(record.getInt("sessionId"));
                            boolean owned=session!=null && context.getPackageName().equals(session.getInstallerPackageName());
                            if(recoveryAction(status.stage,owned,session!=null && session.isSealed())==Recovery.INTERRUPTED) {
                                if(owned) context.getPackageManager().getPackageInstaller().abandonSession(record.getInt("sessionId"));
                                stage(record,"failed","installation_interrupted");
                            } else {
                                // A surviving sealed session may have lost its confirmation Activity.
                                try(PackageInstaller.Session pending=context.getPackageManager().getPackageInstaller().openSession(record.getInt("sessionId"))) {
                                    pending.commit(callback(record).getIntentSender());
                                    emit(status);
                                } catch(Exception e) {
                                    try {context.getPackageManager().getPackageInstaller().abandonSession(record.getInt("sessionId"));} catch(RuntimeException ignored) {}
                                    stage(record,"failed","installation_interrupted");
                                }
                            }
                        }
                    }
                    if(matches)finishAccount(record);
                }
            } catch(Exception ignored) {emit(new InstallationStatus("","failed","","installation_status_unavailable"));}
            finally {PREPARING.set(false);}
        });
    }
    public void retryAccount(String id) {
        EXECUTOR.execute(()->{try {
            JSONObject record=journal.get(id);
            if(record!=null && "installed_login_required".equals(record.optString("stage")) && installedMatches(record,false)) finishAccount(record);
        } catch(Exception ignored) {emit(new InstallationStatus(id,"installed_login_required","","open_app_to_sign_in"));}});
    }
    private static void removeGenerated(File path) {
        File[] files=path.listFiles();if(files!=null) for(File file:files) {if(file.isDirectory()) removeGenerated(file);else file.delete();}path.delete();
    }
}
