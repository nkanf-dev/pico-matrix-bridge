package org.picomatrix.bridge.adapter;

import com.reandroid.apk.ApkModule;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.cert.*;
import java.util.*;
import java.util.zip.*;
import org.json.*;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;

/** Account-free, Android 29 compatible APK preparation. Signing and installation belong to the host. */
public final class AdapterEngine {
    private AdapterEngine() {}
    public enum Route { PASSTHROUGH, PROFILE, ANALYSIS_REQUIRED }
    public static final class Inspection {
        public final Route route;
        public final boolean matrixDetected,profileExact;
        public final long versionCode;
        public final String packageName,profileId,appId,reason,inputSha256;
        private final JSONObject report,profile;
        private final ApplicationProfile implementation;
        private Inspection(Route route,JSONObject report,JSONObject profile,ApplicationProfile implementation,String reason) {
            this.route=route;this.report=report;this.profile=profile;this.implementation=implementation;this.reason=reason;
            JSONObject manifest=report.getJSONObject("manifest");
            this.packageName=manifest.getString("package");
            this.versionCode=versionCode(manifest);
            this.matrixDetected=report.getJSONObject("matrix").getBoolean("detected");
            this.inputSha256=report.getJSONObject("source").getString("sha256");
            JSONObject identity=implementation==null?null:implementation.metadata();
            this.profileExact=route==Route.PROFILE && identity!=null && inputSha256.equals(identity.optString("inputSha256")) &&
                (!identity.has("versionCode") || versionCode==identity.optLong("versionCode",-1));
            this.profileId=profile==null?null:profile.optString("id",null);this.appId=profile==null?null:profile.optString("appId",null);
        }
    }
    public static final class Result {
        public final Path output;
        public final boolean requiresSigning;
        public final String inputSha256,outputSha256,profileId,appId,packageName,targetSignerSha256;
        private Result(Path output,boolean signing,Inspection inspection,String outputHash,String targetSigner) {
            this.output=output;this.requiresSigning=signing;this.inputSha256=inspection.inputSha256;this.outputSha256=outputHash;
            this.profileId=inspection.profileId;this.appId=inspection.appId;
            this.packageName=signing?inspection.profile.getString("outputPackage"):inspection.packageName;
            this.targetSignerSha256=targetSigner;
        }
    }
    static final class Bundle {
        final Path directory;final JSONObject manifest;
        Bundle(Path directory) throws Exception {
            this.directory=directory.toRealPath();manifest=Portable.json(file("bundle.json"));
            Portable.require(manifest.getInt("schema")==1,"Unsupported bundle schema");
            JSONObject files=manifest.getJSONObject("files");
            for(String name:Portable.keys(files)) {
                JSONObject item=files.getJSONObject(name);Path path=file(name);
                Portable.require(Files.size(path)==item.getLong("bytes")&&Portable.sha(path).equals(item.getString("sha256")),"Bundle file identity differs: "+name);
            }
            for(String key:new String[]{"runtime","bootstrap","matrixProfile"}) Portable.require(files.has(manifest.getString(key)),"Unpinned bundle input");
        }
        Path file(String name) throws Exception {
            Portable.require(name.matches("[A-Za-z0-9][A-Za-z0-9._-]*"),"Invalid bundle path");
            Path path=directory.resolve(name);Portable.require(!Files.isSymbolicLink(path)&&Files.isRegularFile(path),"Missing or linked bundle file: "+name);return path;
        }
    }
    private static long versionCode(JSONObject manifest) {
        return (manifest.optLong("versionCodeMajor",0)<<32)|(manifest.optLong("versionCode",0)&0xffffffffL);
    }
    /** Package/version badge lookup. The selected implementation is already authenticated by the host. */
    public static boolean supportsProfile(ApplicationProfile implementation,String packageName,long versionCode) {
        JSONObject profile=implementation==null?null:implementation.metadata();
        return profile!=null && packageName!=null && versionCode>0 && packageName.equals(profile.optString("package"))
            && versionCode==profile.optLong("versionCode",-1);
    }
    /** A matching package may try the profile even when its version has not been validated. */
    public static boolean canAttemptProfile(ApplicationProfile implementation,String packageName) {
        JSONObject profile=implementation==null?null:implementation.metadata();
        return profile!=null && packageName!=null && packageName.equals(profile.optString("package"));
    }
    public static String targetPackage(ApplicationProfile implementation,String originalPackage) {
        Portable.require(originalPackage!=null && originalPackage.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"),"Invalid original package");
        JSONObject profile=implementation==null?null:implementation.metadata();
        if(profile!=null && originalPackage.equals(profile.optString("package"))) {
            String target=profile.optString("outputPackage");
            Portable.require(target.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"),"Invalid target package");
            return target;
        }
        return genericTargetPackage(originalPackage);
    }
    public static String genericTargetPackage(String packageName) {
        try {return "org.picomatrix.a"+Portable.sha(packageName.getBytes(StandardCharsets.UTF_8)).substring(0,9);}
        catch(Exception e) {throw new IllegalStateException("SHA-256 unavailable",e);}
    }
    public static Inspection inspect(File input,File bundle,List<ApplicationProfile> profiles) throws Exception { return inspect(input.toPath(),bundle.toPath(),profiles); }
    public static Inspection inspect(Path input,Path bundle,List<ApplicationProfile> profiles) throws Exception {
        JSONObject report=ApkInspector.inspect(input);Bundle b=Files.isRegularFile(bundle.resolve("bundle.json"))?new Bundle(bundle):null;
        return select(report,b,profiles);
    }
    private static final class Candidate {
        final ApplicationProfile implementation;final JSONObject metadata;final int priority,specificity,versionMatch;
        final long profileVersion;final String key;
        Candidate(ApplicationProfile implementation,JSONObject metadata,int specificity,int versionMatch) {
            this.implementation=implementation;this.metadata=metadata;this.priority=implementation.priority();
            this.specificity=specificity;this.versionMatch=versionMatch;
            JSONObject identity=implementation.metadata();
            this.profileVersion=identity.optLong("profileVersionCode",0);
            this.key=identity.optString("profileKey",identity.optString("id",""));
        }
    }
    static Inspection select(JSONObject report,Bundle bundle,List<ApplicationProfile> profiles) throws Exception {
        String packageName=report.getJSONObject("manifest").getString("package");
        List<Candidate> candidates=new ArrayList<>();
        for(ApplicationProfile implementation:profiles) {
            String matcher=implementation.packageMatcher();
            if(!matcher.equals("*")&&!matcher.equals(packageName))continue;
            JSONObject selected=implementation.select(report);
            if(selected!=null) {
                JSONObject identity=implementation.metadata();
                boolean exact=identity.optString("inputSha256").equals(report.getJSONObject("source").getString("sha256")) &&
                    (!identity.has("versionCode") || identity.getLong("versionCode")==versionCode(report.getJSONObject("manifest")));
                candidates.add(new Candidate(implementation,selected,matcher.equals("*")?0:1,exact?1:0));
            }
        }
        if(!candidates.isEmpty()) {
            candidates.sort(Comparator.comparingInt((Candidate c)->c.priority).thenComparingInt(c->c.specificity)
                .thenComparingInt(c->c.versionMatch).thenComparingLong(c->c.profileVersion).reversed()
                .thenComparing(c->c.key));
            Candidate chosen=candidates.get(0);
            return new Inspection(Route.PROFILE,report,chosen.metadata,chosen.implementation,
                chosen.versionMatch==1?"Checked application override":"Profile attempt; targeted inputs still require verification");
        }
        if(!report.getJSONObject("matrix").getBoolean("detected"))return new Inspection(Route.PASSTHROUGH,report,null,null,"Ordinary application retains original install identity and signature");
        return new Inspection(Route.ANALYSIS_REQUIRED,report,null,null,"No installed profile accepts this Matrix dependency");
    }
    public static Result prepare(File original,File bundle,File output,byte[] certificate,String hostPackage,String hostSigner,List<ApplicationProfile> profiles) throws Exception {
        return prepare(original.toPath(),bundle.toPath(),output.toPath(),certificate,hostPackage,hostSigner,profiles);
    }
    public static Result prepare(Path original,Path bundleDir,Path outputUnsigned,byte[] targetCertificateDer,String hostPackage,String hostCertificateSha256,List<ApplicationProfile> profiles) throws Exception {
        Path source=original.toRealPath(),output=outputUnsigned.toAbsolutePath().normalize();
        Portable.require(!source.equals(output)&&!Files.exists(output),"Output must be a new copy");
        JSONObject report=ApkInspector.inspect(source);Bundle bundle=Files.isRegularFile(bundleDir.resolve("bundle.json"))?new Bundle(bundleDir):null;
        Inspection inspection=select(report,bundle,profiles);
        if(inspection.route==Route.PASSTHROUGH)return new Result(source,false,inspection,inspection.inputSha256,null);
        Portable.require(inspection.route!=Route.ANALYSIS_REQUIRED,inspection.reason);
        Portable.require(bundle!=null,"Compatibility runtime bundle missing");
        Portable.require(hostPackage.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")&&hostCertificateSha256.matches("[a-fA-F0-9]{64}"),"Invalid host identity");
        X509Certificate cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(targetCertificateDer));
        Portable.require(Arrays.equals(cert.getEncoded(),targetCertificateDer),"Target certificate must be one canonical DER X509 certificate");
        String targetSigner=Portable.sha(targetCertificateDer);JSONObject metadata=inspection.profile;
        Portable.require(!report.getJSONObject("manifest").has("sharedUserId"),"Shared-UID applications require analysis");
        Files.createDirectories(output.getParent());Path work=Files.createTempDirectory(output.getParent(),"matrix-prepare-");
        try {
            JSONObject embedded=embedded(source,bundle,work,metadata,targetSigner,hostPackage,hostCertificateSha256.toLowerCase(Locale.ROOT));
            Map<String,byte[]> replacements=inspection.implementation.prepare(source,report,targetCertificateDer,metadata.getString("outputPackage"));
            Path staged=work.resolve("unsigned.apk");
            ApkRewriter.adapt(source,staged,metadata,report,embedded,replacements);
            verifyCopy(source,staged,metadata,embedded,replacements.keySet());
            inspection.implementation.verify(source,staged,replacements);
            Portable.require(inspection.inputSha256.equals(Portable.sha(source)),"Original changed during preparation");
            String hash=Portable.sha(staged);Files.move(staged,output,StandardCopyOption.ATOMIC_MOVE);
            return new Result(output,true,inspection,hash,targetSigner);
        } finally { Portable.deleteTree(work); }
    }
    public static byte[] entry(ZipFile zip,String name,int limit) throws Exception {
        ZipEntry entry=zip.getEntry(name);Portable.require(entry!=null,"Missing APK entry: "+name);
        try(InputStream input=zip.getInputStream(entry)){return Portable.read(input,limit);}
    }
    private static JSONObject embedded(Path original,Bundle bundle,Path work,JSONObject profile,String signer,String host,String hostSigner) throws Exception {
        String target=profile.getString("outputPackage"),launch=profile.optString("launchActivity"),label=profile.optString("label","Matrix Bridge");
        if(launch.isEmpty())try(ApkModule apk=ApkModule.loadApkFile(original.toFile())) {
            var manifest=apk.getAndroidManifestBlock();var main=manifest.getMainActivity();int launcherCount=0;
            Iterator<com.reandroid.arsc.chunk.xml.ResXmlElement> elements=manifest.getApplicationElement().recursiveElements();
            while(elements.hasNext())if(ApkRewriter.launcherFilter(elements.next()))launcherCount++;
            Portable.require(main!=null&&"activity".equals(main.getName())&&launcherCount==1,"Missing or ambiguous launcher requires analysis");
            launch=main.searchAttributeByName("name").getValueAsString();
            if(launch.startsWith("."))launch=profile.getString("package")+launch;else if(!launch.contains("."))launch=profile.getString("package")+"."+launch;
        }
        Path payload=work.resolve("matrix-runtime.zip");JSONObject libraries=new JSONObject();Map<String,JSONObject> nativeRules=new HashMap<>();JSONArray natives=bundle.manifest.getJSONArray("native");
        for(int i=0;i<natives.length();i++){JSONObject rule=natives.getJSONObject(i);nativeRules.put(rule.getString("entry"),rule);}
        try(ZipFile template=new ZipFile(bundle.file(bundle.manifest.getString("runtime")).toFile());ZipOutputStream out=new ZipOutputStream(Files.newOutputStream(payload))) {
            Set<String> names=new HashSet<>();
            for(ZipEntry item:Collections.list(template.entries())) {
                String name=item.getName();Portable.require(names.add(name),"Duplicate runtime entry");byte[] data=entry(template,name,96*1024*1024);
                if(name.endsWith(".so")) {
                    JSONObject rule=nativeRules.get(name);Portable.require(rule!=null&&Portable.sha(data).equals(rule.getString("sha256")),"Unknown runtime native library");
                    if(rule.getInt("replacements")>0)data=ApkRewriter.route(data,rule.getInt("replacements"),target);
                    libraries.put(name.substring(name.lastIndexOf('/')+1),Portable.sha(data));
                } else Portable.require(name.matches("classes[0-9]*\\.dex"),"Unexpected runtime payload entry");
                ZipEntry output=new ZipEntry(name);output.setTime(0);out.putNextEntry(output);out.write(data);out.closeEntry();
            }
            Portable.require(names.containsAll(nativeRules.keySet()),"Runtime native dependency missing");
        }
        JSONObject config=new JSONObject().put("schema",1).put("package",target).put("originalPackage",profile.getString("package")).put("appId",profile.getString("appId")).put("launchActivity",launch).put("label",label)
            .put("payloadSha256",Portable.sha(payload)).put("libraries",libraries).put("provisionerPackage",host).put("provisionerSignerSha256",hostSigner)
            .put("targetSignerSha256",signer).put("account",profile.getJSONObject("account"));
        Path configPath=work.resolve("matrix-embedded.json");Portable.json(configPath,config);
        byte[] bootstrap=Files.readAllBytes(bundle.file(bundle.manifest.getString("bootstrap")));Set<String> bootstrapTypes=new HashSet<>();
        for(var cls:new DexBackedDexFile(Opcodes.forApi(29),bootstrap).getClasses())bootstrapTypes.add(cls.getType());
        int count=0;Set<String> dexNames=new HashSet<>();
        try(ZipFile client=new ZipFile(original.toFile())) {for(ZipEntry item:Collections.list(client.entries()))if(item.getName().matches("classes[0-9]*\\.dex")) {
            count++;dexNames.add(item.getName());for(var cls:new DexBackedDexFile(Opcodes.forApi(29),entry(client,item.getName(),128*1024*1024)).getClasses())Portable.require(!bootstrapTypes.contains(cls.getType()),"Bootstrap class collides with application");
        }}
        Portable.require(count>0,"No original DEX");for(int i=1;i<=count;i++)Portable.require(dexNames.contains(i==1?"classes.dex":"classes"+i+".dex"),"Non-contiguous original DEX");
        JSONObject additions=new JSONObject();addition(additions,"classes"+(count+1)+".dex",bundle.file(bundle.manifest.getString("bootstrap")));
        addition(additions,"assets/matrix-runtime.zip",payload);addition(additions,"assets/matrix-embedded.json",configPath);addition(additions,"assets/matrix-runtime-profile.json",bundle.file(bundle.manifest.getString("matrixProfile")));
        return new JSONObject().put("config",config).put("dex",new JSONObject().put("applicationCollisions",0)).put("additions",additions);
    }
    private static void addition(JSONObject additions,String entry,Path path) throws Exception { additions.put(entry,new JSONObject().put("path",path.toString()).put("sha256",Portable.sha(path)).put("bytes",Files.size(path))); }
    private static boolean signature(String name) {String n=name.toUpperCase(Locale.ROOT);return n.startsWith("META-INF/")&&(n.endsWith(".SF")||n.endsWith(".RSA")||n.endsWith(".DSA")||n.endsWith(".EC")||n.equals("META-INF/MANIFEST.MF"));}
    private static void verifyCopy(Path original,Path adapted,JSONObject profile,JSONObject embedded,Set<String> replacements) throws Exception {
        Set<String> changed=Portable.keys(profile.getJSONObject("libraries"));changed.add("AndroidManifest.xml");
        changed.addAll(replacements);
        try(ZipFile before=new ZipFile(original.toFile());ZipFile after=new ZipFile(adapted.toFile())) {
            Set<String> names=new HashSet<>();for(ZipEntry e:Collections.list(after.entries()))Portable.require(names.add(e.getName()),"Duplicate prepared APK entry");
            JSONObject additions=embedded.getJSONObject("additions");
            for(ZipEntry old:Collections.list(before.entries())) {
                String name=old.getName();names.remove(name);if(signature(name))continue;ZipEntry replacement=after.getEntry(name);
                Portable.require(replacement!=null,"Original entry removed: "+name);
                if(!changed.contains(name))Portable.require(old.getSize()==replacement.getSize()&&old.getCrc()==replacement.getCrc(),"Unrelated APK entry changed: "+name);
            }
            Portable.require(names.equals(Portable.keys(additions)),"Unexpected APK additions");
            for(String name:names)Portable.require(Portable.sha(entry(after,name,96*1024*1024)).equals(additions.getJSONObject(name).getString("sha256")),"Embedded addition changed");
            JSONObject manifest=new BinaryManifest(entry(after,"AndroidManifest.xml",8*1024*1024)).read();
            Portable.require(manifest.getString("package").equals(profile.getString("outputPackage")),"Prepared package identity differs");
        }
    }
}
