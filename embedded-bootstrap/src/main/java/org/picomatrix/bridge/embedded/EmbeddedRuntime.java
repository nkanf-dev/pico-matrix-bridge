package org.picomatrix.bridge.embedded;

import android.content.Context;
import dalvik.system.DexClassLoader;
import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import java.util.zip.*;
import org.json.*;

/** Loads only hash-pinned code shipped inside this signed application. */
public final class EmbeddedRuntime {
    private static ClassLoader loader;
    private static JSONObject config;
    public static synchronized JSONObject config(Context context) throws Exception {
        if(config==null) {
            try(InputStream in=context.getAssets().open("matrix-embedded.json")) {
                config=new JSONObject(new String(read(in,64*1024),java.nio.charset.StandardCharsets.UTF_8));
            }
            if(config.getInt("schema")!=1 || !context.getPackageName().equals(config.getString("package")))
                throw new SecurityException("Embedded runtime identity mismatch");
        }
        return config;
    }
    private static byte[] read(InputStream in,int limit) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int n;
        while((n=in.read(b))!=-1) { if(n>limit-out.size()) throw new IOException("Embedded input too large");out.write(b,0,n); }
        return out.toByteArray();
    }
    private static String hash(File file) throws Exception {
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try(InputStream in=new FileInputStream(file)) { byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1) digest.update(b,0,n); }
        StringBuilder hex=new StringBuilder();for(byte b:digest.digest()) hex.append(String.format(Locale.ROOT,"%02x",b&255));return hex.toString();
    }
    private static void writeChecked(InputStream in,File destination,String expected,long limit) throws Exception {
        if(destination.isFile() && hash(destination).equals(expected)) return;
        File part=new File(destination.getParentFile(),destination.getName()+".part");
        if(part.exists() && !part.delete()) throw new IOException("Cannot reset runtime staging file");
        try {
            try(FileOutputStream out=new FileOutputStream(part)) {
                // Android 14 requires dynamically loaded code to be read-only.
                if(!part.setReadOnly()) throw new IOException("Cannot protect runtime file");
                byte[] b=new byte[65536];long total=0;int n;
                while((n=in.read(b))!=-1) { total+=n;if(total>limit) throw new IOException("Embedded file too large");out.write(b,0,n); }
                out.getFD().sync();
            }
            if(!hash(part).equals(expected)) throw new SecurityException("Embedded file hash mismatch");
            Files.move(part.toPath(),destination.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally { part.delete(); }
    }
    public static synchronized ClassLoader load(Context context) throws Exception {
        if(loader!=null) return loader;
        JSONObject info=config(context);String sha=info.getString("payloadSha256");
        if(!sha.matches("[a-f0-9]{64}")) throw new SecurityException("Invalid runtime digest");
        File root=new File(context.getCodeCacheDir(),"matrix-runtime/"+sha), libs=new File(root,"lib64");
        if(!libs.isDirectory() && !libs.mkdirs()) throw new IOException("Cannot create runtime directory");
        File payload=new File(root,"runtime.zip");
        try(InputStream in=context.getAssets().open("matrix-runtime.zip")) { writeChecked(in,payload,sha,96L*1024*1024); }
        JSONObject libraries=info.getJSONObject("libraries");
        try(ZipFile zip=new ZipFile(payload)) {
            for(String name:sortedKeys(libraries)) {
                if(!name.matches("lib[a-zA-Z0-9_+.-]+\\.so")) throw new SecurityException("Invalid library entry");
                ZipEntry entry=zip.getEntry("lib/arm64-v8a/"+name);
                if(entry==null) throw new IOException("Missing embedded library");
                try(InputStream in=zip.getInputStream(entry)) { writeChecked(in,new File(libs,name),libraries.getString(name),32L*1024*1024); }
            }
        }
        // Framework-only parent: vendor AndroidX/Kotlin versions never shadow
        // the game's own dependencies. Context, Bundle and Activity cross this boundary.
        loader=new DexClassLoader(payload.getPath(),root.getPath(),libs.getPath(),Context.class.getClassLoader());
        android.util.Log.i("MatrixBridge","embedded runtime loaded in target process");
        return loader;
    }
    private static List<String> sortedKeys(JSONObject object) {
        List<String> keys=new ArrayList<>();object.keys().forEachRemaining(keys::add);Collections.sort(keys);return keys;
    }
    public static boolean ready(Context c) throws Exception {
        return (Boolean)load(c).loadClass("org.picomatrix.bridge.EmbeddedAccount").getMethod("ready",Context.class).invoke(null,c);
    }
    public static void provision(Context c,String grant) throws Exception {
        load(c).loadClass("org.picomatrix.bridge.EmbeddedAccount").getMethod("provision",Context.class,String.class).invoke(null,c,grant);
    }
    public static AutoCloseable login(android.app.Activity activity,Runnable ready) throws Exception {
        return (AutoCloseable)load(activity).loadClass("org.picomatrix.bridge.EmbeddedAccount")
            .getMethod("login",android.app.Activity.class,Runnable.class).invoke(null,activity,ready);
    }
    public static Object broker(String method,Class<?>[] signature,Object... args) {
        try {
            ClassLoader current=loader;if(current==null) throw new IllegalStateException("Runtime not loaded");
            return current.loadClass("com.bytedance.pico.matrix.server.ServerBrokerJni").getMethod(method,signature).invoke(null,args);
        } catch(java.lang.reflect.InvocationTargetException e) {
            Throwable cause=e.getCause();if(cause instanceof RuntimeException r) throw r;
            if(cause instanceof Error error) throw error;throw new IllegalStateException("Embedded broker call failed",cause);
        } catch(ReflectiveOperationException e) {throw new IllegalStateException("Embedded broker contract differs",e);}
    }
    private EmbeddedRuntime() {}
}
