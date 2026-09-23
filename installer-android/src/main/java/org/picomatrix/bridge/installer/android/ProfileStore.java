package org.picomatrix.bridge.installer.android;

import android.content.Context;
import android.content.pm.PackageInfo;
import dalvik.system.DexClassLoader;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.zip.ZipFile;
import org.json.JSONObject;
import org.picomatrix.bridge.adapter.ApplicationProfile;

/** Publisher-signed profile APKs; code is loaded only after full verification. */
public final class ProfileStore {
    public static final long MAX_BYTES=32L*1024*1024;
    private final Context context;
    private final String packageName,assetName,trustedSignerSha256;
    private final File directory;

    public static final class Loaded {
        public final ApplicationProfile implementation;
        public final long version;
        public final String sha256;
        public final File apk;
        private Loaded(ApplicationProfile implementation,long version,String sha256,File apk) {
            this.implementation=implementation;this.version=version;this.sha256=sha256;this.apk=apk;
        }
    }

    public ProfileStore(Context context,String packageName,String bundledAsset,String trustedSignerSha256) {
        this.context=context.getApplicationContext();this.packageName=packageName;this.assetName=bundledAsset;
        if(!packageName.matches("org\\.picomatrix\\.bridge\\.profile\\.[a-z][a-z0-9_]*") ||
            (bundledAsset!=null&&!bundledAsset.matches("matrix-profile-[a-z][a-z0-9_]*\\.apk")) ||
            trustedSignerSha256==null || !trustedSignerSha256.matches("[a-f0-9]{64}"))
            throw new IllegalArgumentException("Invalid profile identity or trust anchor");
        this.trustedSignerSha256=trustedSignerSha256;
        directory=new File(this.context.getFilesDir(),"matrix-profiles/"+packageName);
    }

    public synchronized Loaded current() throws Exception {
        if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("profile_storage");
        File pointer=new File(directory,"active.json");
        if(pointer.isFile()) {
            try {
                JSONObject active=readPointer(pointer);
                String hash=active.getString("sha256");
                File file=new File(directory,hash+".apk");
                Loaded selected=load(file,hash);
                if(selected.version!=active.getLong("version"))writePointer(pointer,selected);
                return selected;
            } catch(Exception ignored) {}
        }
        File previous=new File(directory,"previous.json");
        if(previous.isFile())try {
            JSONObject prior=readPointer(previous);
            Loaded valid=load(new File(directory,prior.getString("sha256")+".apk"),prior.getString("sha256"));
            writePointer(pointer,valid);return valid;
        } catch(Exception ignored) {}
        if(assetName==null)throw new IOException("profile_unavailable");
        File bundled=File.createTempFile("profile-seed-",".apk",directory);
        try {
            try(InputStream in=context.getAssets().open(assetName);OutputStream out=new FileOutputStream(bundled)) {copyBounded(in,out,MAX_BYTES);}
            return activate(bundled,null,0,true);
        } finally {bundled.delete();}
    }

    /** A failed candidate never replaces the active pointer or the previous APK. */
    public synchronized Loaded activate(File candidate,String expectedSha256,long expectedVersion) throws Exception {
        return activate(candidate,expectedSha256,expectedVersion,false);
    }

    private Loaded activate(File candidate,String expectedSha256,long expectedVersion,boolean seed) throws Exception {
        if(!directory.isDirectory()&&!directory.mkdirs())throw new IOException("profile_storage");
        if(!candidate.isFile()||candidate.length()<=0||candidate.length()>MAX_BYTES)throw new IOException("profile_size");
        String hash=LocalSigner.hash(candidate);
        if(expectedSha256!=null&&!hash.equals(expectedSha256))throw new SecurityException("profile_digest");
        File destination=new File(directory,hash+".apk");
        if(destination.isFile() && (destination.canWrite() || !hash.equals(LocalSigner.hash(destination))))
            Files.delete(destination.toPath());
        boolean created=false;
        try {
        if(!destination.isFile()) {
            File staged=File.createTempFile("profile-",".apk",directory);
            try {
                Files.copy(candidate.toPath(),staged.toPath(),StandardCopyOption.REPLACE_EXISTING);
                if(!hash.equals(LocalSigner.hash(staged)))throw new SecurityException("profile_changed");
                if(!staged.setReadOnly())throw new IOException("profile_read_only");
                Files.move(staged.toPath(),destination.toPath(),StandardCopyOption.ATOMIC_MOVE);
                created=true;
            } finally {staged.delete();}
        }
        Loaded next=load(destination,hash);
        if(!seed && next.version!=expectedVersion)throw new SecurityException("profile_version");
        File active=new File(directory,"active.json");
        if(active.isFile()) {
            try {
                JSONObject old=readPointer(active);
                Loaded current=load(new File(directory,old.getString("sha256")+".apk"),old.getString("sha256"));
                if(!current.implementation.metadata().getString("package").equals(next.implementation.metadata().getString("package")) ||
                    !current.implementation.metadata().getString("outputPackage").equals(next.implementation.metadata().getString("outputPackage")))
                    throw new SecurityException("profile_target_changed");
                if(!seed && next.version<=current.version)throw new IOException("profile_not_newer");
                Files.copy(active.toPath(),new File(directory,"previous.json").toPath(),StandardCopyOption.REPLACE_EXISTING);
            } catch(Exception error) {if(!seed)throw error;}
        }
        writePointer(active,next);
        return next;
        } catch(Exception error) {
            if(created)destination.delete();
            throw error;
        }
    }

    private Loaded load(File file,String expectedHash) throws Exception {
        if(!file.isFile()||file.length()<=0||file.length()>MAX_BYTES||!file.canRead()||file.canWrite())throw new IOException("profile_file");
        if(!LocalSigner.hash(file).equals(expectedHash))throw new SecurityException("profile_digest");
        if(!LocalSigner.verify(file).equals(trustedSignerSha256))
            throw new SecurityException("profile_signer");
        PackageInfo info=context.getPackageManager().getPackageArchiveInfo(file.getAbsolutePath(),0);
        if(info==null||!packageName.equals(info.packageName)||info.getLongVersionCode()<=0)throw new SecurityException("profile_package");
        JSONObject recipe;
        try(ZipFile zip=new ZipFile(file)) {
            var entry=zip.getEntry("assets/profile.json");
            if(entry==null||entry.getSize()>4*1024*1024)throw new IOException("profile_metadata");
            try(InputStream in=zip.getInputStream(entry)) {recipe=new JSONObject(new String(readBounded(in,4*1024*1024),StandardCharsets.UTF_8));}
        }
        if(recipe.getInt("profileApi")!=ApplicationProfile.API_VERSION)throw new IOException("profile_api");
        String versionUtc=recipe.getString("profileVersionUtc");
        long version=recipe.getLong("profileVersionCode");
        if(version<1||version>2100000000L||!versionUtc.equals(Instant.ofEpochSecond(version).toString())||
            version!=info.getLongVersionCode()||!versionUtc.equals(info.versionName))
            throw new SecurityException("profile_version");
        String className=recipe.getString("entryClass");
        if(!className.matches("[a-zA-Z_][a-zA-Z0-9_]*(\\.[a-zA-Z_][a-zA-Z0-9_]*)+"))throw new IOException("profile_class");
        ClassLoader loader=new DexClassLoader(file.getAbsolutePath(),context.getCodeCacheDir().getAbsolutePath(),null,
            ApplicationProfile.class.getClassLoader());
        Object instance=Class.forName(className,true,loader).getConstructor(JSONObject.class).newInstance(recipe);
        if(!(instance instanceof ApplicationProfile))throw new SecurityException("profile_api");
        ApplicationProfile profile=(ApplicationProfile)instance;
        if(!packageName.equals("org.picomatrix.bridge.profile."+profile.metadata().getString("profileKey")))
            throw new SecurityException("profile_identity");
        if(profile.metadata().optLong("profileVersionCode",-1)!=version)
            throw new SecurityException("profile_version");
        return new Loaded(profile,info.getLongVersionCode(),expectedHash,file);
    }

    private static void writePointer(File pointer,Loaded profile) throws Exception {
        File part=new File(pointer.getParentFile(),pointer.getName()+".part");
        try {
            byte[] bytes=new JSONObject().put("sha256",profile.sha256).put("version",profile.version).toString().getBytes(StandardCharsets.UTF_8);
            try(FileOutputStream out=new FileOutputStream(part)){out.write(bytes);out.getFD().sync();}
            Files.move(part.toPath(),pointer.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally {part.delete();}
    }
    private static JSONObject readPointer(File file) throws Exception {
        if(file.length()>4096)throw new IOException("profile_pointer");
        JSONObject pointer=new JSONObject(new String(Files.readAllBytes(file.toPath()),StandardCharsets.UTF_8));
        if(!pointer.getString("sha256").matches("[a-f0-9]{64}"))throw new IOException("profile_pointer");
        return pointer;
    }
    public static void copyBounded(InputStream in,OutputStream out,long limit) throws IOException {
        byte[] buffer=new byte[65536];long total=0;int n;
        while((n=in.read(buffer))!=-1){total+=n;if(total>limit)throw new IOException("profile_size");out.write(buffer,0,n);}
    }
    private static byte[] readBounded(InputStream in,int limit) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();copyBounded(in,out,limit);return out.toByteArray();
    }
}
