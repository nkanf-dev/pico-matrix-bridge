package org.picomatrix.bridge.adapter;

import com.reandroid.apk.ApkModule;
import com.reandroid.archive.ByteInputSource;
import com.reandroid.arsc.chunk.xml.*;
import com.reandroid.arsc.value.ValueType;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Application-neutral APK writer and Matrix native routing primitives. */
public final class ApkRewriter {
    private ApkRewriter() {}
    private static final byte[] ORIGINAL="com.bytedance.pico.matrix\0".getBytes(StandardCharsets.US_ASCII);
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
            // Preserve original component implementation and XR metadata.
            main.removeElementsIf(ApkRewriter::launcherFilter);
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
    public static boolean launcherFilter(ResXmlElement filter) {
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
    public static void adapt(Path input,Path output,JSONObject metadata,JSONObject inspected,JSONObject embedded,
            Map<String,byte[]> replacements) throws Exception {
        Portable.require(!Files.exists(output),"Prepared output already exists");
        String original=metadata.getString("package"),target=metadata.getString("outputPackage");
        Portable.require(original.equals(inspected.getJSONObject("manifest").getString("package")),"Profile package differs from input");
        Portable.require(target.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"),"Invalid target package");
        Portable.require(inspected.getJSONObject("matrix").getJSONArray("dexReferences").length()==0,"DEX Matrix routing requires analysis");
        Portable.require(target.equals(embedded.getJSONObject("config").getString("package")),"Embedded package differs");
        JSONObject libraries=metadata.getJSONObject("libraries");
        Set<String> actual=new HashSet<>();JSONArray detected=inspected.getJSONObject("matrix").getJSONArray("nativeReferences");
        for(int i=0;i<detected.length();i++)actual.add(detected.getString(i));
        Portable.require(actual.equals(Portable.keys(libraries)),"Profile does not cover every native Matrix reference");
        Portable.require(!replacements.containsKey("AndroidManifest.xml"),"Manifest replacement belongs to the core");
        for(String name:replacements.keySet())Portable.require(!libraries.has(name)&&!name.startsWith("META-INF/")&&replacements.get(name).length<=48*1024*1024,"Invalid profile replacement");
        try(ApkModule apk=ApkModule.loadApkFile(input.toFile())) {
            manifest(apk,original,target,embedded,metadata.optString("label",null));
            JSONObject additions=embedded.getJSONObject("additions");
            for(String name:new TreeSet<>(Portable.keys(additions))) {
                Portable.require(name.matches("classes[0-9]+\\.dex") || Portable.set("assets/matrix-runtime.zip","assets/matrix-embedded.json","assets/matrix-runtime-profile.json").contains(name),"Unexpected embedded entry");
                Portable.require(apk.getInputSource(name)==null,"Embedded entry overwrites original");
                JSONObject item=additions.getJSONObject(name);byte[] bytes=Files.readAllBytes(Paths.get(item.getString("path")));
                Portable.require(Portable.sha(bytes).equals(item.getString("sha256"))&&bytes.length==item.getLong("bytes"),"Embedded input differs");
                ByteInputSource addition=new ByteInputSource(bytes,name);addition.setMethod(0);apk.add(addition);
            }
            for(String name:new TreeSet<>(replacements.keySet())) {
                var before=apk.getInputSource(name);Portable.require(before!=null,"Profile replacement target missing: "+name);
                ByteInputSource patched=new ByteInputSource(replacements.get(name),name);patched.setMethod(before.getMethod());apk.add(patched);
            }
            for(String name:new TreeSet<>(Portable.keys(libraries))) {
                JSONObject rule=libraries.getJSONObject(name);var before=apk.getInputSource(name);
                Portable.require(before!=null,"Native Matrix reference missing: "+name);
                byte[] bytes;try(var stream=before.openStream()){bytes=ApkInspector.bounded(stream,16*1024*1024);}
                Portable.require(Portable.sha(bytes).equals(rule.getString("sha256")),"Native Matrix input differs");
                byte[] routed=route(bytes,rule.getInt("replacements"),target);
                ByteInputSource patched=new ByteInputSource(routed,name);patched.setMethod(before.getMethod());apk.add(patched);
            }
            apk.setApkSignatureBlock(null);
            for(var source:apk.listInputSources()) {
                String name=source.getAlias().toUpperCase(Locale.ROOT);
                if(name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC") || name.endsWith(".SF") || name.equals("META-INF/MANIFEST.MF")))apk.removeInputSource(source.getAlias());
            }
            try(com.reandroid.archive.writer.ApkFileWriter writer=apk.createApkFileWriter(output.toFile())) {
                var alignment=new com.reandroid.archive.writer.ZipAligner();alignment.setDefaultAlignment(4);
                alignment.setFileAlignment(com.reandroid.archive.writer.ZipAligner.PREDICATE_NATIVE_LIBS,16384);
                writer.setZipAligner(alignment);writer.write();
            }
        } catch(Exception error) {Files.deleteIfExists(output);throw error;}
    }
}
