package org.picomatrix.bridge.installer.android;

import android.content.Context;
import android.content.pm.PackageManager;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import com.android.apksig.ApkSigner;
import com.android.apksig.ApkVerifier;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.*;
import javax.security.auth.x500.X500Principal;

final class LocalSigner {
    private static final String ALIAS="org.picomatrix.bridge.copy-signing.v1";
    static synchronized KeyStore.PrivateKeyEntry identity() throws Exception {
        KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);
        if(!store.containsAlias(ALIAS)) {
            KeyPairGenerator generator=KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,"AndroidKeyStore");
            generator.initialize(new KeyGenParameterSpec.Builder(ALIAS,KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setKeySize(2048).setDigests(KeyProperties.DIGEST_SHA256,KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setCertificateSubject(new X500Principal("CN=PICO Matrix Bridge"))
                .setCertificateSerialNumber(BigInteger.ONE)
                .setCertificateNotBefore(new Date(1577836800000L))
                .setCertificateNotAfter(new Date(4102444800000L)).build());
            generator.generateKeyPair();
        }
        KeyStore.Entry entry=store.getEntry(ALIAS,null);
        if(!(entry instanceof KeyStore.PrivateKeyEntry)) throw new GeneralSecurityException("Signing identity unavailable");
        return (KeyStore.PrivateKeyEntry)entry;
    }
    static void sign(File input,File output,KeyStore.PrivateKeyEntry identity) throws Exception {
        if(output.exists()) throw new IOException("Signing output already exists");
        ApkSigner.SignerConfig config=new ApkSigner.SignerConfig.Builder("matrix-bridge",identity.getPrivateKey(),
            Collections.singletonList((X509Certificate)identity.getCertificate())).build();
        try {
            new ApkSigner.Builder(Collections.singletonList(config)).setInputApk(input).setOutputApk(output)
                .setMinSdkVersion(29).setV1SigningEnabled(true).setV2SigningEnabled(true)
                .setV3SigningEnabled(true).setV4SigningEnabled(false).build().sign();
            String signer=verify(output);
            if(!signer.equals(hash(identity.getCertificate().getEncoded()))) throw new GeneralSecurityException("Unexpected output signer");
        } catch(Exception e) { output.delete();throw e; }
    }
    static String verify(File apk) throws Exception {
        ApkVerifier.Result result=new ApkVerifier.Builder(apk).setMinCheckedPlatformVersion(29).build().verify();
        if(!result.isVerified() || result.getSignerCertificates().size()!=1)
            throw new GeneralSecurityException("APK signature verification failed");
        return hash(result.getSignerCertificates().get(0).getEncoded());
    }
    static String installedSigner(Context context,String packageName) throws Exception {
        android.content.pm.Signature[] signers=context.getPackageManager()
            .getPackageInfo(packageName,PackageManager.GET_SIGNING_CERTIFICATES).signingInfo.getApkContentsSigners();
        if(signers.length!=1) throw new GeneralSecurityException("Ambiguous package signer");
        return hash(signers[0].toByteArray());
    }
    static String hash(byte[] bytes) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    static String hash(File file) throws Exception {
        MessageDigest md=MessageDigest.getInstance("SHA-256");
        try(InputStream in=new FileInputStream(file)) { byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1) md.update(b,0,n); }
        return hex(md.digest());
    }
    static String hex(byte[] bytes) { StringBuilder out=new StringBuilder(bytes.length*2);for(byte b:bytes) out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString(); }
}
