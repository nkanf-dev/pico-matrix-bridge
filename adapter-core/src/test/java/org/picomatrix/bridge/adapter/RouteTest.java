package org.picomatrix.bridge.adapter;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.nio.file.*;
import java.util.Map;

public class RouteTest {
    private static final String LIB="lib/arm64-v8a/libloader.so";
    private ApplicationProfile profile() {
        return new ApplicationProfile() {
            @Override public JSONObject metadata() {
                return new JSONObject().put("id","example-profile").put("package","example.target")
                    .put("outputPackage","org.picomatrix.bridge.example").put("inputSha256","original")
                    .put("appId","client123").put("versionCode",10703);
            }
            @Override public Map<String,byte[]> prepare(Path original,JSONObject inspection,byte[] certificate,String target) {return Map.of();}
            @Override public void verify(Path original,Path unsigned,Map<String,byte[]> replacements) {}
        };
    }
    private AdapterEngine.Bundle bundle(Path dir) throws Exception {
        Path path=dir.resolve("runtime.zip");Files.write(path,new byte[]{1,2,3});
        JSONObject files=new JSONObject().put("runtime.zip",new JSONObject().put("sha256",Portable.sha(path)).put("bytes",Files.size(path)));
        JSONObject rule=new JSONObject().put("sha256","loaderhash").put("replacements",1);
        JSONObject manifest=new JSONObject().put("schema",1).put("bootstrap","runtime.zip").put("runtime","runtime.zip")
            .put("matrixProfile","runtime.zip").put("files",files)
            .put("generic",new JSONObject().put("libraries",new JSONObject().put(LIB,rule))
                .put("appIdMetadataNames",new JSONArray().put("app_id"))
                .put("account",new JSONObject().put("agwKey","vendor-protocol")));
        Portable.json(dir.resolve("bundle.json"),manifest);return new AdapterEngine.Bundle(dir);
    }
    private JSONObject report(String pkg,String hash) {
        return new JSONObject().put("manifest",new JSONObject().put("package",pkg).put("versionCode",10703)
                .put("metadata",new JSONArray().put(new JSONObject().put("name","app_id").put("value","client123"))))
            .put("source",new JSONObject().put("sha256",hash))
            .put("managedRuntime",new JSONObject().put("requiresManagedCodeReview",false))
            .put("matrix",new JSONObject().put("detected",true).put("dexReferences",new JSONArray())
                .put("libraries",new JSONArray().put(new JSONObject().put("entry",LIB).put("sha256","loaderhash"))));
    }
    @Test public void aMatchingImplementationOwnsAttemptsAcrossAppVersions() throws Exception {
        Path dir=Files.createTempDirectory("matrix-route-");try {
            var bundle=bundle(dir);var profile=profile();
            assertTrue(AdapterEngine.select(report("example.target","original"),bundle,profile).profileExact);
            assertEquals(AdapterEngine.Route.PROFILE,AdapterEngine.select(report("example.target","changed"),bundle,profile).route);
            JSONObject newer=report("example.target","changed");newer.getJSONObject("manifest").put("versionCode",10704);
            assertFalse(AdapterEngine.select(newer,bundle,profile).profileExact);
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(newer,null,null).route);
            assertEquals(AdapterEngine.Route.GENERIC,AdapterEngine.select(report("another.native.app","changed"),bundle,profile).route);
            assertTrue(AdapterEngine.canAttemptProfile(profile,"example.target"));
            assertTrue(AdapterEngine.supportsProfile(profile,"example.target",10703));
            assertFalse(AdapterEngine.supportsProfile(profile,"example.target",10704));
        } finally {Portable.deleteTree(dir);}
    }
    @Test public void ambiguousIdentityDexRoutingAndUnknownNativeLibrariesRequireAnalysis() throws Exception {
        Path dir=Files.createTempDirectory("matrix-route-");try {
            var bundle=bundle(dir);JSONObject report=report("another.native.app","original");
            report.getJSONObject("manifest").getJSONArray("metadata").put(new JSONObject().put("name","app_id").put("value","different123"));
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report,bundle,null).route);
            report=report("another.native.app","original");report.getJSONObject("matrix").getJSONArray("dexReferences").put("dependency");
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report,bundle,null).route);
            report=report("another.native.app","original");report.getJSONObject("matrix").getJSONArray("libraries").getJSONObject(0).put("sha256","unknown");
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report,bundle,null).route);
        } finally {Portable.deleteTree(dir);}
    }
    @Test public void bundleTamperAndPathEscapeFailBeforeAdaptation() throws Exception {
        Path dir=Files.createTempDirectory("matrix-bundle-");try {
            bundle(dir);Files.write(dir.resolve("runtime.zip"),new byte[]{4,5,6});
            assertThrows(IllegalArgumentException.class,()->new AdapterEngine.Bundle(dir));
            bundle(dir);JSONObject manifest=Portable.json(dir.resolve("bundle.json"));manifest.getJSONObject("files").put("../outside",new JSONObject());Portable.json(dir.resolve("bundle.json"),manifest);
            assertThrows(IllegalArgumentException.class,()->new AdapterEngine.Bundle(dir));
        } finally {Portable.deleteTree(dir);}
    }
    @Test public void launcherReplacementRetainsDeepLinkFilters() {
        var manifest=new com.reandroid.arsc.chunk.xml.AndroidManifestBlock();manifest.setPackageName("ordinary.app");
        var activity=manifest.getOrCreateMainActivity("ordinary.app.MainActivity");
        var deepLink=activity.newElement("intent-filter");
        deepLink.newElement("action").getOrCreateAndroidAttribute("name",0x01010003).setValueAsString("android.intent.action.VIEW");
        deepLink.newElement("category").getOrCreateAndroidAttribute("name",0x01010003).setValueAsString("android.intent.category.BROWSABLE");
        assertEquals(2,activity.getElementsCount("intent-filter"));
        activity.removeElementsIf(ApkRewriter::launcherFilter);
        assertEquals(1,activity.getElementsCount("intent-filter"));assertSame(deepLink,activity.getElement("intent-filter"));
    }
    @Test public void inspectionExposesMatrixDetectionAndAndroidLongVersionCode() throws Exception {
        JSONObject input=report("ordinary.app","hash");input.getJSONObject("manifest").put("versionCode",-1).put("versionCodeMajor",2);
        input.getJSONObject("matrix").put("detected",false);
        var ordinary=AdapterEngine.select(input,null,null);
        assertFalse(ordinary.matrixDetected);assertEquals((2L<<32)|0xffffffffL,ordinary.versionCode);
        input.getJSONObject("matrix").put("detected",true);
        var dependency=AdapterEngine.select(input,null,null);
        assertTrue(dependency.matrixDetected);assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,dependency.route);
    }
    @Test public void targetLookupUsesSelectedImplementation() {
        var profile=profile();
        assertEquals("org.picomatrix.bridge.example",AdapterEngine.targetPackage(profile,"example.target"));
        assertFalse(AdapterEngine.canAttemptProfile(profile,"other.package"));
        String generic=AdapterEngine.targetPackage(null,"another.native.app");
        assertTrue(generic.matches("org\\.picomatrix\\.a[0-9a-f]{9}"));
    }
}
