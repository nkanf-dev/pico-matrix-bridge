package org.picomatrix.bridge.adapter;

import com.reandroid.apk.ApkModule;
import com.reandroid.archive.ByteInputSource;
import com.reandroid.arsc.chunk.xml.*;
import com.reandroid.arsc.value.ValueType;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.json.*;

/** Guarded VD research profile. Produces an unsigned APK copy, never installs. */
public final class ResearchAdapter {
    private static final byte[] ORIGINAL="com.bytedance.pico.matrix\0".getBytes(StandardCharsets.US_ASCII);
    private static String hash(byte[] bytes) throws Exception { return Portable.hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    public static JSONObject admission(JSONObject inspection,JSONObject profile) {
        if(!"research".equals(profile.getString("status")) || !profile.getString("inputSha256").equals(inspection.getJSONObject("source").getString("sha256")))
            throw new IllegalArgumentException("input is not the pinned research sample");
        if(!profile.getString("package").equals(inspection.getJSONObject("manifest").getString("package")))
            throw new IllegalArgumentException("profile package differs from input");
        JSONObject assessment=profile.optJSONObject("staticAssessment");
        String status=assessment==null?"unreviewed":assessment.optString("status","unreviewed");
        JSONArray blockers=assessment==null?null:assessment.optJSONArray("blockers");
        // A discovered loader is a dependency, not permission to rebuild the whole application.
        boolean admitted="ready-for-device-validation".equals(status) && blockers!=null && blockers.length()==0;
        return new JSONObject().put("profile",profile.getString("id")).put("source",inspection.getJSONObject("source"))
            .put("status",status).put("adaptationAllowed",admitted).put("functionalValidation",false)
            .put("blockers",blockers==null?new JSONArray().put(new JSONObject().put("code","STATIC_REVIEW_REQUIRED")):blockers);
    }
    public static void requireAdmission(JSONObject report) {
        if(!report.getBoolean("adaptationAllowed"))
            throw new IllegalArgumentException("static preflight prevents adaptation: "+report.getJSONArray("blockers"));
    }
    public static byte[] route(byte[] bytes,int expected) {
        return route(bytes,expected,"org.picomatrix.bridge");
    }
    public static byte[] route(byte[] bytes,int expected,String target) {
        byte[] destination=(target+"\0").getBytes(StandardCharsets.US_ASCII);
        if(destination.length>ORIGINAL.length) throw new IllegalArgumentException("native route does not fit");
        if(bytes.length<4 || bytes[0]!=127 || bytes[1]!='E' || bytes[2]!='L' || bytes[3]!='F') throw new IllegalArgumentException("not ELF");
        byte[] copy=bytes.clone();int count=0;
        for(int i=0;i<=bytes.length-ORIGINAL.length;i++) {
            boolean match=true;for(int j=0;j<ORIGINAL.length;j++) if(bytes[i+j]!=ORIGINAL[j]) { match=false;break; }
            if(match) { Arrays.fill(copy,i,i+ORIGINAL.length,(byte)0);System.arraycopy(destination,0,copy,i,destination.length);count++;i+=ORIGINAL.length-1; }
        }
        if(count!=expected || count==0) throw new IllegalArgumentException("unexpected native routing count");
        return copy;
    }
    private static String renameOwned(String value,String old,String replacement) {
        return value.equals(old) || value.startsWith(old+".") ? replacement+value.substring(old.length()) : value;
    }
    private static void manifest(ApkModule apk,String original,String replacement,JSONObject embedded,String displayLabel) {
        AndroidManifestBlock manifest=apk.getAndroidManifestBlock();
        if(manifest.getManifestElement().getAttributeCount()==0) throw new IllegalArgumentException("empty manifest");
        Iterator<ResXmlElement> elements=manifest.recursiveElements();
        while(elements.hasNext()) {
            ResXmlElement element=elements.next();String kind=element.getName();
            Iterator<ResXmlAttribute> attrs=element.getAttributes();
            while(attrs.hasNext()) {
                ResXmlAttribute attr=attrs.next();String name=attr.getName();
                if("sharedUserId".equals(name)) throw new IllegalArgumentException("shared-UID apps are not supported");
                if(attr.getValueType()!=ValueType.STRING) continue;
                String value=attr.getValueAsString();
                if(value==null) continue;
                if((name.equals("name") && Portable.set("application","activity","activity-alias","service","receiver","provider","instrumentation").contains(kind)) || name.equals("targetActivity") || name.equals("appComponentFactory")) {
                    if(value.startsWith(".")) attr.setValueAsString(original+value);
                    else if(!value.contains(".")) attr.setValueAsString(original+"."+value);
                } else if(name.equals("authorities") && "application".equals(element.getParentElement().getName())) {
                    String[] authorities=value.split(";");for(int i=0;i<authorities.length;i++) authorities[i]=renameOwned(authorities[i],original,replacement);
                    attr.setValueAsString(String.join(";",authorities));
                } else if((name.equals("name") && Portable.set("permission","uses-permission").contains(kind)) || Portable.set("permission","readPermission","writePermission","taskAffinity").contains(name)) {
                    attr.setValueAsString(renameOwned(value,original,replacement));
                }
            }
        }
        // Keep compiled resource namespaces and numeric IDs intact; only the install identity changes.
        if(!original.equals(replacement)) manifest.setPackageName(replacement);
        if(displayLabel!=null) manifest.setApplicationLabel(displayLabel);
        ResXmlElement main=manifest.getMainActivity();
        if(main!=null && displayLabel!=null) {
            main.removeAttributesWithId(0x01010001);
            ResXmlAttribute label=main.newAttribute("label",0x01010001);
            label.setNamespace("http://schemas.android.com/apk/res/android","android");label.setValueAsString(displayLabel);
        }
        ResXmlElement query=manifest.getManifestElement().getOrCreateElement("queries").newElement("package");
        ResXmlAttribute name=query.newAttribute("name",0x01010003);name.setNamespace("http://schemas.android.com/apk/res/android","android");
        name.setValueAsString(embedded==null?"org.picomatrix.bridge":embedded.getJSONObject("config").getString("provisionerPackage"));
        if(embedded!=null) {
            if(main==null || !embedded.getJSONObject("config").getString("launchActivity").equals(main.searchAttributeByName("name").getValueAsString()))
                throw new IllegalArgumentException("original launch activity differs");
            // VD's pinned main activity has one launcher filter. Preserve all
            // original component implementation and XR metadata.
            main.removeElementsIf(ResearchAdapter::launcherFilter);
            ResXmlElement app=manifest.getManifestElement().getElement("application");
            Iterator<ResXmlElement> existing=app.getElements();
            while(existing.hasNext()) {
                ResXmlElement component=existing.next();ResXmlAttribute componentName=component.searchAttributeByName("name");
                if(componentName!=null && Portable.set("org.picomatrix.bridge.embedded.LaunchActivity","org.picomatrix.bridge.embedded.ProvisioningProvider").contains(componentName.getValueAsString()))
                    throw new IllegalArgumentException("Embedded component already declared by original");
                ResXmlAttribute authority=component.searchAttributeByName("authorities");
                if(authority!=null && Arrays.asList(authority.getValueAsString().split(";")).contains(replacement+".matrix.provision"))
                    throw new IllegalArgumentException("Provisioning authority conflicts with original");
            }
            if(manifest.getUsesPermission("android.permission.INTERNET")==null)manifest.addUsesPermission("android.permission.INTERNET");
            ResXmlElement launcher=app.newElement("activity");
            androidString(launcher,"name",0x01010003,"org.picomatrix.bridge.embedded.LaunchActivity");
            launcher.getOrCreateAndroidAttribute("exported",0x01010010).setValueAsBoolean(true);
            ResXmlAttribute theme=launcher.getOrCreateAndroidAttribute("theme",0x01010000);
            theme.setValueType(ValueType.REFERENCE);theme.setData(16974401);
            ResXmlElement filter=launcher.newElement("intent-filter");
            androidString(filter.newElement("action"),"name",0x01010003,"android.intent.action.MAIN");
            androidString(filter.newElement("category"),"name",0x01010003,"android.intent.category.LAUNCHER");
            ResXmlElement receiver=app.newElement("provider");
            androidString(receiver,"name",0x01010003,"org.picomatrix.bridge.embedded.ProvisioningProvider");
            androidString(receiver,"authorities",0x01010018,replacement+".matrix.provision");
            receiver.getOrCreateAndroidAttribute("exported",0x01010010).setValueAsBoolean(true);
        }
        manifest.refreshFull();
    }
    static boolean launcherFilter(ResXmlElement filter) {
        if(!"intent-filter".equals(filter.getName()))return false;
        boolean main=false,launcher=false;Iterator<ResXmlElement> children=filter.getElements();
        while(children.hasNext()) {
            ResXmlElement child=children.next();ResXmlAttribute name=child.searchAttributeByName("name");
            if(name==null)continue;String value=name.getValueAsString();
            if("action".equals(child.getName())&&"android.intent.action.MAIN".equals(value))main=true;
            if("category".equals(child.getName())&&"android.intent.category.LAUNCHER".equals(value))launcher=true;
        }
        return main&&launcher;
    }
    private static void androidString(ResXmlElement element,String name,int id,String value) {
        element.getOrCreateAndroidAttribute(name,id).setValueAsString(value);
    }
    public static JSONObject adapt(Path input,Path output,JSONObject profile) throws Exception {
        return adapt(input,output,profile,null);
    }
    public static JSONObject adapt(Path input,Path output,JSONObject profile,JSONObject preparedManaged) throws Exception {
        return adapt(input,output,profile,preparedManaged,ApkInspector.inspect(input),false);
    }
    static JSONObject adapt(Path input,Path output,JSONObject profile,JSONObject preparedManaged,JSONObject inspected,boolean generic) throws Exception {
        if(Files.exists(output)) throw new IllegalArgumentException("research output already exists");
        JSONObject assessment=admission(inspected,profile);
        if(preparedManaged==null) requireAdmission(assessment);
        else if(!generic && (!"vd-embedded-v5".equals(profile.optString("recipe")) ||
                !profile.getString("inputSha256").equals(preparedManaged.getString("inputSha256")) ||
                !preparedManaged.getBoolean("controlFlowUnchanged") || !preparedManaged.getBoolean("onlyIntegrityConstantsChanged") ||
                !preparedManaged.getBoolean("metadataIdentityUnchanged")))
            throw new IllegalArgumentException("VD managed preparation is incomplete");
        if(preparedManaged!=null && !generic) {
            JSONArray patches=preparedManaged.getJSONArray("patches");
            Set<String> assemblies=new HashSet<>();
            for(int i=0;i<patches.length();i++) assemblies.add(patches.getJSONObject(i).getString("assembly"));
            if(patches.length()!=3 || !assemblies.equals(Portable.set(profile.getJSONObject("managedSigner").getString("assembly"),
                    profile.getJSONObject("managedLoaderIntegrity").getString("assembly"),
                    profile.getJSONObject("managedSignerHashes").getString("assembly"))))
                throw new IllegalArgumentException("VD managed preparation must cover all integrity checks");
        }
        String original=profile.getString("package"),target=profile.getString("outputPackage");
        if(!original.equals(inspected.getJSONObject("manifest").getString("package")) || !target.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")) throw new IllegalArgumentException("invalid package identity");
        if(inspected.getJSONObject("matrix").getJSONArray("dexReferences").length()!=0) throw new IllegalArgumentException("native-only profile cannot rewrite DEX routing");
        JSONObject libraries=profile.getJSONObject("libraries");
        JSONArray detected=inspected.getJSONObject("matrix").getJSONArray("nativeReferences");
        Set<String> actual=new HashSet<>();for(int i=0;i<detected.length();i++) actual.add(detected.getString(i));
        if(!actual.equals(Portable.keys(libraries))) throw new IllegalArgumentException("profile does not cover every native Matrix reference");
        JSONArray changes=new JSONArray();
        Files.createDirectories(output.toAbsolutePath().getParent());
        try(ApkModule apk=ApkModule.loadApkFile(input.toFile())) {
            JSONObject embedded=preparedManaged==null?null:preparedManaged.getJSONObject("embedded");
            if(embedded!=null && (!target.equals(embedded.getJSONObject("config").getString("package")) ||
                embedded.getJSONObject("dex").getInt("applicationCollisions")!=0)) throw new IllegalArgumentException("embedded package mismatch");
            manifest(apk,original,target,embedded,profile.optString("label",original.equals("VirtualDesktop.Android")?"Virtual Desktop · Matrix Bridge":null));
            if(embedded!=null) {
                JSONObject additions=embedded.getJSONObject("additions");
                for(String entry:new TreeSet<>(Portable.keys(additions))) {
                    if(!(entry.matches("classes[0-9]+\\.dex") || Portable.set("assets/matrix-runtime.zip","assets/matrix-embedded.json","assets/matrix-runtime-profile.json").contains(entry)))
                        throw new IllegalArgumentException("unexpected embedded entry");
                    if(apk.getInputSource(entry)!=null) throw new IllegalArgumentException("embedded entry overwrites original");
                    JSONObject item=additions.getJSONObject(entry);byte[] bytes;
                    try(var in=Files.newInputStream(Paths.get(item.getString("path")))) {bytes=ApkInspector.bounded(in,96*1024*1024);}
                    if(!hash(bytes).equals(item.getString("sha256"))) throw new IllegalArgumentException("embedded input hash mismatch");
                    ByteInputSource source=new ByteInputSource(bytes,entry);source.setMethod(0);apk.add(source);
                    changes.put(new JSONObject().put("entry",entry).put("after",hash(bytes)).put("operation","embed"));
                }
            }
            if(preparedManaged!=null && !generic) {
                JSONObject aotRule=profile.getJSONObject("aotSignerHashes");
                JSONObject proof=preparedManaged.getJSONObject("aotSignerHashes");
                String aotEntry=aotRule.getString("entry");
                if(!aotEntry.equals(proof.getString("entry")) || !proof.getBoolean("controlFlowUnchanged") ||
                        proof.getInt("instructionCount")!=6 || proof.getJSONArray("constants").length()!=3 ||
                        !aotRule.getString("sha256").equals(proof.getString("originalSha256")))
                    throw new IllegalArgumentException("AOT signer comparisons were not verified");
                byte[] aotBefore;
                try(var stream=apk.getInputSource(aotEntry).openStream()) {
                    aotBefore=ApkInspector.bounded(stream,16*1024*1024);
                    if(!hash(aotBefore).equals(aotRule.getString("sha256")))
                        throw new IllegalArgumentException("AOT image differs from profile");
                }
                byte[] aotAfter;
                try(var stream=Files.newInputStream(Paths.get(proof.getString("path")))) { aotAfter=ApkInspector.bounded(stream,16*1024*1024); }
                if(aotAfter.length!=aotBefore.length || !hash(aotAfter).equals(proof.getString("sha256")))
                    throw new IllegalArgumentException("AOT preparation identity differs");
                ByteInputSource nativePatched=new ByteInputSource(aotAfter,aotEntry);
                nativePatched.setMethod(apk.getInputSource(aotEntry).getMethod());apk.add(nativePatched);
                changes.put(new JSONObject().put("entry",aotEntry).put("before",hash(aotBefore)).put("after",hash(aotAfter)));
                JSONObject rule=profile.getJSONObject("managedSigner");String entry=rule.getString("entry");
                byte[] before;
                try(var stream=apk.getInputSource(entry).openStream()) { before=ApkInspector.bounded(stream,32*1024*1024); }
                if(!hash(before).equals(rule.getString("sha256"))) throw new IllegalArgumentException("managed store differs from VD profile");
                byte[] after;
                try(var stream=Files.newInputStream(Paths.get(preparedManaged.getString("path")))) { after=ApkInspector.bounded(stream,32*1024*1024); }
                if(!hash(after).equals(preparedManaged.getString("sha256")) || after.length<before.length || after.length>before.length+16*1024*1024)
                    throw new IllegalArgumentException("managed preparation identity differs");
                ByteInputSource patched=new ByteInputSource(after,entry);patched.setMethod(apk.getInputSource(entry).getMethod());apk.add(patched);
                changes.put(new JSONObject().put("entry",entry).put("before",hash(before)).put("after",hash(after)));
            }
            for(String entry:new TreeSet<>(Portable.keys(libraries))) {
                JSONObject rule=libraries.getJSONObject(entry);byte[] bytes;
                try(var stream=apk.getInputSource(entry).openStream()) { bytes=ApkInspector.bounded(stream,16*1024*1024); }
                if(!hash(bytes).equals(rule.getString("sha256"))) throw new IllegalArgumentException("loader differs from profile");
                byte[] routed=route(bytes,rule.getInt("replacements"),embedded==null?"org.picomatrix.bridge":target);
                if(preparedManaged!=null && !generic && entry.equals(profile.getJSONObject("managedLoaderIntegrity").getString("library"))) {
                    JSONArray patches=preparedManaged.getJSONArray("patches");boolean bound=false;
                    for(int i=0;i<patches.length();i++) {
                        JSONObject patch=patches.getJSONObject(i);
                        if(entry.equals(patch.optString("library")))
                            bound=hash(routed).equals(patch.getString("adaptedLibrarySha256")) && routed.length==patch.getInt("loaderBytes");
                    }
                    if(!bound) throw new IllegalArgumentException("managed hash is not bound to the routed loader");
                }
                ByteInputSource patched=new ByteInputSource(routed,entry);patched.setMethod(apk.getInputSource(entry).getMethod());apk.add(patched);
                changes.put(new JSONObject().put("entry",entry).put("before",hash(bytes)).put("after",hash(routed)));
            }
            apk.setApkSignatureBlock(null);
            for(var source:apk.listInputSources()) {
                String name=source.getAlias().toUpperCase(Locale.ROOT);
                if(name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC") || name.endsWith(".SF") || name.equals("META-INF/MANIFEST.MF"))) apk.removeInputSource(source.getAlias());
            }
            try (com.reandroid.archive.writer.ApkFileWriter writer=apk.createApkFileWriter(output.toFile())) {
                com.reandroid.archive.writer.ZipAligner alignment=new com.reandroid.archive.writer.ZipAligner();
                alignment.setDefaultAlignment(4);
                alignment.setFileAlignment(com.reandroid.archive.writer.ZipAligner.PREDICATE_NATIVE_LIBS,16384);
                writer.setZipAligner(alignment);writer.write();
            }
        } catch(Exception e) { Files.deleteIfExists(output);throw e; }
        return new JSONObject().put("profile",profile.getString("id")).put("original",inspected.getJSONObject("source")).put("package",target).put("changes",changes).put("output",output.toString()).put("signed",false).put("functionalValidation",false);
    }
}
