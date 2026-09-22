package org.picomatrix.bridge.account;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** The owning application UID controls its encrypted account state. */
public final class SessionStore {
    private static final String ALIAS="org.picomatrix.bridge.account.v1";
    private static SessionStore instance;
    public static synchronized SessionStore get(Context context) {
        if(instance==null) {
            Context application=context.getApplicationContext();
            instance=new SessionStore(application==null?context:application);
        }
        return instance;
    }
    static final class Snapshot {
        final long generation;final JSONObject state;
        Snapshot(long generation,JSONObject state) {this.generation=generation;this.state=state;}
    }
    synchronized Snapshot snapshot() throws Exception {return new Snapshot(generation(),read());}
    private final AtomicFile file;
    private final SessionGeneration generation=new SessionGeneration();
    private SessionStore(Context context) { file=new AtomicFile(new File(context.getNoBackupFilesDir(),"account.sealed")); }
    private KeyStore keys() throws Exception { KeyStore ks=KeyStore.getInstance("AndroidKeyStore");ks.load(null);return ks; }
    private SecretKey key() throws Exception {
        SecretKey existing=(SecretKey)keys().getKey(ALIAS,null);
        if(existing!=null) return existing;
        KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
        generator.init(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setRandomizedEncryptionRequired(true).build());
        return generator.generateKey();
    }
    public synchronized long generation() { return generation.current(); }
    public synchronized JSONObject read() throws Exception {
        if(!file.getBaseFile().exists() && !new File(file.getBaseFile()+".bak").exists()) return null;
        byte[] sealed;
        try(InputStream in=file.openRead()) { sealed=AccountIo.read(in,256*1024); }
        if(sealed.length<29 || sealed[0]!=1) throw new IOException("Invalid account storage");
        SecretKey secret=(SecretKey)keys().getKey(ALIAS,null);
        if(secret==null) throw new IOException("Account key unavailable");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE,secret,new GCMParameterSpec(128,Arrays.copyOfRange(sealed,1,13)));
        return new JSONObject(new String(cipher.doFinal(sealed,13,sealed.length-13),StandardCharsets.UTF_8));
    }
    public synchronized void save(long expected,JSONObject value) throws Exception {
        generation.check(expected);
        byte[] plain=value.toString().getBytes(StandardCharsets.UTF_8);
        if(plain.length>240*1024) throw new IOException("Account storage limit");
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key());
        byte[] encrypted=cipher.doFinal(plain);FileOutputStream out=file.startWrite();
        try { out.write(1);out.write(cipher.getIV());out.write(encrypted);file.finishWrite(out); }
        catch(Exception e) { file.failWrite(out);throw e; }
    }
    public synchronized void check(long expected) throws AccountClient.Failure {
        generation.check(expected);
    }
    public synchronized void clear() throws Exception { generation.invalidate();file.delete();keys().deleteEntry(ALIAS); }
}
