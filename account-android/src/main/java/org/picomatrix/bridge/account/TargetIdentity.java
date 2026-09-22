package org.picomatrix.bridge.account;

import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.util.Locale;
import org.json.JSONObject;

/** Account identity comes from the installed APK, never a global game constant. */
public final class TargetIdentity {
    public final String appId, packageName;
    final String agwKey;
    public TargetIdentity(String appId,String packageName,String agwKey) {
        if(appId==null || !appId.matches("[A-Za-z0-9_-]{1,64}") || packageName==null ||
            !packageName.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+") ||
            agwKey==null || !agwKey.matches("[\\x21-\\x7e]{1,256}"))
            throw new IllegalArgumentException("Invalid application account identity");
        this.appId=appId;this.packageName=packageName;this.agwKey=agwKey;
    }
    static TargetIdentity fromConfig(JSONObject config,String installedPackage) throws Exception {
        if(config.getInt("schema")!=1 || !installedPackage.equals(config.getString("package")))
            throw new SecurityException("Embedded account identity mismatch");
        return new TargetIdentity(config.getString("appId"),installedPackage,config.getJSONObject("account").getString("agwKey"));
    }
    public static TargetIdentity embedded(Context context) throws Exception {
        try(InputStream in=context.getAssets().open("matrix-embedded.json")) {
            return fromConfig(new JSONObject(new String(AccountIo.read(in,64*1024),StandardCharsets.UTF_8)),context.getPackageName());
        }
    }
    static TargetIdentity installed(Context context,String appId,String packageName) throws Exception {
        TargetIdentity identity=embedded(context.createPackageContext(packageName,0));
        if(!identity.appId.equals(appId)) throw new SecurityException("Installed application ID differs");
        return identity;
    }
    static Signature signer(Context context,String packageName) throws Exception {
        var info=context.getPackageManager().getPackageInfo(packageName,PackageManager.GET_SIGNING_CERTIFICATES);
        if(info.signingInfo==null) throw new SecurityException("Application signer unavailable");
        Signature[] signers=info.signingInfo.getApkContentsSigners();
        if(signers==null || signers.length!=1) throw new SecurityException("Ambiguous application signer");
        return signers[0];
    }
    /** APK certificate digest used by installer/provider trust checks. */
    public static String signerSha256(Context context,String packageName) throws Exception {
        return AccountClient.hex(MessageDigest.getInstance("SHA-256").digest(signer(context,packageName).toByteArray()));
    }
    /** Passport expects the X.509 public-key digest rather than the certificate digest. */
    String passportSignature(Context context) throws Exception {
        byte[] publicKey=CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(signer(context,packageName).toByteArray())).getPublicKey().getEncoded();
        return AccountClient.hex(MessageDigest.getInstance("SHA-256").digest(publicKey)).toUpperCase(Locale.ROOT);
    }
}
