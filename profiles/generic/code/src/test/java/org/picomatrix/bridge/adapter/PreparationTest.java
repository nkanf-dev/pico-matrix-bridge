package org.picomatrix.bridge.adapter;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.cert.CertificateFactory;
import java.util.*;
import java.util.zip.*;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.immutable.ImmutableClassDef;
import org.jf.dexlib2.writer.io.MemoryDataStore;
import org.jf.dexlib2.writer.pool.DexPool;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;

/** A source-only generic native APK fixture verifies the complete preparation route. */
public class PreparationTest {
    @Test public void genericProfileOnlyAcceptsCheckedNativeMatrixInputs() throws Exception {
        String library="lib/arm64-v8a/libloader.so";
        JSONObject recipe=new JSONObject().put("schema",1).put("profile",new JSONObject().put("profileKey","generic")
                .put("packageMatcher","*").put("priority",0).put("package","*").put("outputPackage","*"))
            .put("libraries",new JSONObject().put(library,new JSONObject().put("sha256","known").put("replacements",1)))
            .put("appIdMetadataNames",new JSONArray().put("app_id")).put("account",new JSONObject());
        var profile=new GenericMatrixProfile(recipe);
        JSONObject report=new JSONObject().put("manifest",new JSONObject().put("package","example.app")
                .put("metadata",new JSONArray().put(new JSONObject().put("name","app_id").put("value","known_app_id"))))
            .put("source",new JSONObject().put("sha256","original"))
            .put("managedRuntime",new JSONObject().put("requiresManagedCodeReview",false))
            .put("matrix",new JSONObject().put("detected",true).put("dexReferences",new JSONArray())
                .put("libraries",new JSONArray().put(new JSONObject().put("entry",library).put("sha256","known"))));
        assertNotNull(profile.select(report));
        JSONObject unchecked=new JSONObject(report.toString());unchecked.getJSONObject("matrix").put("detected",false);
        assertNull(profile.select(unchecked));
        unchecked=new JSONObject(report.toString());unchecked.getJSONObject("managedRuntime").put("requiresManagedCodeReview",true);
        assertNull(profile.select(unchecked));
        unchecked=new JSONObject(report.toString());unchecked.getJSONObject("matrix").getJSONArray("dexReferences").put("Lunknown/Managed;");
        assertNull(profile.select(unchecked));
        unchecked=new JSONObject(report.toString());unchecked.getJSONObject("matrix").getJSONArray("libraries")
            .put(new JSONObject().put("entry","lib/arm64-v8a/unknown.so").put("sha256","unknown"));
        assertNull(profile.select(unchecked));
        unchecked=new JSONObject(report.toString());unchecked.getJSONObject("manifest").getJSONArray("metadata")
            .put(new JSONObject().put("name","app_id").put("value","second_app_id"));
        assertNull(profile.select(unchecked));
    }
    private byte[] dex(String type) throws Exception {
        var clazz=new ImmutableClassDef(type,1,"Ljava/lang/Object;",Collections.emptyList(),null,Collections.emptyList(),Collections.emptyList(),Collections.emptyList());
        DexPool pool=new DexPool(Opcodes.forApi(29));pool.internClass(clazz);MemoryDataStore out=new MemoryDataStore();pool.writeTo(out);return Arrays.copyOf(out.getBuffer(),out.getSize());
    }
    private void zip(Path file,Map<String,byte[]> entries) throws Exception {
        try(ZipOutputStream zip=new ZipOutputStream(Files.newOutputStream(file))){for(var entry:entries.entrySet()){zip.putNextEntry(new ZipEntry(entry.getKey()));zip.write(entry.getValue());zip.closeEntry();}}
    }
    @Test public void genericPreparationUsesSeparateSignerIdentitiesAndRetainsInput() throws Exception {
        Path dir=Files.createTempDirectory("matrix-prepare-test-");try {
            String library="lib/arm64-v8a/libloader.so";byte[] loader="\177ELFcom.bytedance.pico.matrix\0".getBytes(StandardCharsets.US_ASCII);
            var manifest=new AndroidManifestBlock();manifest.setPackageName("example.nativeapp");manifest.setApplicationLabel("Original label");
            manifest.getOrCreateMainActivity("example.nativeapp.MainActivity");var metadata=manifest.getApplicationElement().newElement("meta-data");
            metadata.getOrCreateAndroidAttribute("name",0x01010003).setValueAsString("app_id");metadata.getOrCreateAndroidAttribute("value",0x01010024).setValueAsString("generic_app_123");manifest.refreshFull();
            Path input=dir.resolve("input.apk");Map<String,byte[]> entries=new HashMap<>();entries.put("AndroidManifest.xml",manifest.getBytes());entries.put("classes.dex",dex("Lexample/nativeapp/MainActivity;"));entries.put(library,loader);zip(input,entries);
            String originalHash=Portable.sha(input);Path bundle=dir.resolve("bundle");Files.createDirectory(bundle);
            zip(bundle.resolve("runtime.zip"),Collections.singletonMap("classes.dex",dex("Lruntime/Only;")));Files.write(bundle.resolve("bootstrap.dex"),dex("Lorg/picomatrix/bridge/embedded/LaunchActivity;"));
            Portable.json(bundle.resolve("matrix.json"),new JSONObject().put("source","fixture"));
            JSONObject files=new JSONObject();for(String name:new String[]{"runtime.zip","bootstrap.dex","matrix.json"})files.put(name,new JSONObject().put("bytes",Files.size(bundle.resolve(name))).put("sha256",Portable.sha(bundle.resolve(name))));
            Portable.json(bundle.resolve("bundle.json"),new JSONObject().put("schema",1).put("runtime","runtime.zip").put("bootstrap","bootstrap.dex").put("matrixProfile","matrix.json").put("files",files).put("native",new JSONArray()));
            JSONObject generic=new JSONObject().put("schema",1).put("profile",new JSONObject().put("profileKey","generic").put("package","*").put("outputPackage","*"))
                .put("libraries",new JSONObject().put(library,new JSONObject().put("sha256",Portable.sha(loader)).put("replacements",1)))
                .put("appIdMetadataNames",new JSONArray().put("app_id")).put("account",new JSONObject().put("agwKey","protocol-fixture"));
            var profiles=List.<ApplicationProfile>of(new GenericMatrixProfile(generic));
            assertEquals(AdapterEngine.Route.PROFILE,AdapterEngine.inspect(input,bundle,profiles).route);
            byte[] cert;try(InputStream in=getClass().getResourceAsStream("/portable-test-certificate.pem")){cert=CertificateFactory.getInstance("X.509").generateCertificate(in).getEncoded();}
            String hostSigner=String.join("",Collections.nCopies(64,"1"));Path output=dir.resolve("adapted.apk");
            var result=AdapterEngine.prepare(input,bundle,output,cert,"host.package",hostSigner,profiles);
            assertTrue(result.requiresSigning);assertEquals("generic_app_123",result.appId);assertEquals(originalHash,Portable.sha(input));assertEquals(Portable.sha(output),result.outputSha256);
            assertNotEquals("example.nativeapp",result.packageName);assertEquals(AdapterEngine.targetPackage(null,"example.nativeapp"),result.packageName);assertEquals(Portable.sha(cert),result.targetSignerSha256);
            try(ZipFile apk=new ZipFile(output.toFile())) {
                JSONObject config=new JSONObject(new String(AdapterEngine.entry(apk,"assets/matrix-embedded.json",10000),StandardCharsets.UTF_8));
                assertEquals("example.nativeapp",config.getString("originalPackage"));assertEquals(hostSigner,config.getString("provisionerSignerSha256"));assertEquals(Portable.sha(cert),config.getString("targetSignerSha256"));
                assertTrue(ApkInspector.contains(AdapterEngine.entry(apk,library,10000),(result.packageName+"\0").getBytes(StandardCharsets.US_ASCII)));
                assertNotNull(apk.getEntry("classes2.dex"));
            }
            try(var apk=com.reandroid.apk.ApkModule.loadApkFile(output.toFile())) {assertEquals("Original label",apk.getAndroidManifestBlock().getApplicationLabelString());assertNotNull(apk.getAndroidManifestBlock().getUsesPermission("android.permission.INTERNET"));}
            assertThrows(IllegalArgumentException.class,()->AdapterEngine.prepare(input,bundle,output,cert,"host.package",hostSigner,profiles));
        } finally {Portable.deleteTree(dir);}
    }
}
