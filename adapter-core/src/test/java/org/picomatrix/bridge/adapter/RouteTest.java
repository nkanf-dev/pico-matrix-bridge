package org.picomatrix.bridge.adapter;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.nio.file.*;

public class RouteTest {
    private static final String LIB="lib/arm64-v8a/libpxrplatformloader.so";
    private AdapterEngine.Bundle bundle(Path dir) throws Exception {
        JSONObject profile=new JSONObject().put("id","pinned-vd").put("package","VirtualDesktop.Android").put("outputPackage","org.picomatrix.bridge.vd").put("inputSha256","original").put("appId","client123").put("versionCode",10703).put("appVersion","1.34.22.0");
        JSONObject recipe=new JSONObject().put("schema",1).put("profile",profile);Path path=dir.resolve("recipe.json");Portable.json(path,recipe);
        JSONObject rule=new JSONObject().put("sha256","loaderhash").put("replacements",1);
        JSONObject manifest=new JSONObject().put("schema",1).put("recipe","recipe.json").put("bootstrap","recipe.json").put("runtime","recipe.json").put("matrixProfile","recipe.json")
            .put("files",new JSONObject().put("recipe.json",new JSONObject().put("sha256",Portable.sha(path)).put("bytes",Files.size(path))))
            .put("generic",new JSONObject().put("libraries",new JSONObject().put(LIB,rule)).put("appIdMetadataNames",new JSONArray().put("app_id")).put("account",new JSONObject().put("agwKey","vendor-protocol")));
        Portable.json(dir.resolve("bundle.json"),manifest);return new AdapterEngine.Bundle(dir);
    }
    private JSONObject report(String pkg,String hash) {
        return new JSONObject().put("manifest",new JSONObject().put("package",pkg).put("versionCode",10703).put("metadata",new JSONArray().put(new JSONObject().put("name","app_id").put("value","client123"))))
            .put("source",new JSONObject().put("sha256",hash)).put("managedRuntime",new JSONObject().put("requiresManagedCodeReview",false))
            .put("matrix",new JSONObject().put("detected",true).put("dexReferences",new JSONArray()).put("libraries",new JSONArray().put(new JSONObject().put("entry",LIB).put("sha256","loaderhash"))));
    }
    @Test public void knownPackageMismatchNeverFallsThroughToOtherwiseEligibleGenericRoute() throws Exception {
        Path dir=Files.createTempDirectory("matrix-route-");try {
            var bundle=bundle(dir);
            assertEquals(AdapterEngine.Route.PROFILE,AdapterEngine.select(report("VirtualDesktop.Android","original"),bundle).route);
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report("VirtualDesktop.Android","changed"),bundle).route);
            assertEquals(AdapterEngine.Route.GENERIC,AdapterEngine.select(report("another.native.app","changed"),bundle).route);
        } finally {Portable.deleteTree(dir);}
    }
    @Test public void ambiguousIdentityDexRoutingAndUnknownNativeLibrariesRequireAnalysis() throws Exception {
        Path dir=Files.createTempDirectory("matrix-route-");try {
            var bundle=bundle(dir);JSONObject report=report("another.native.app","original");
            report.getJSONObject("manifest").getJSONArray("metadata").put(new JSONObject().put("name","app_id").put("value","different123"));
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report,bundle).route);
            report=report("another.native.app","original");report.getJSONObject("matrix").getJSONArray("dexReferences").put("dependency");
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report,bundle).route);
            report=report("another.native.app","original");report.getJSONObject("matrix").getJSONArray("libraries").getJSONObject(0).put("sha256","unknown");
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report,bundle).route);
        } finally {Portable.deleteTree(dir);}
    }
    @Test public void bundleTamperAndPathEscapeFailBeforeAdaptation() throws Exception {
        Path dir=Files.createTempDirectory("matrix-bundle-");try {
            bundle(dir);Files.write(dir.resolve("recipe.json"),new byte[]{1,2,3});
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
        activity.removeElementsIf(ResearchAdapter::launcherFilter);
        assertEquals(1,activity.getElementsCount("intent-filter"));
        assertSame(deepLink,activity.getElement("intent-filter"));
    }

    @Test public void profileBadgeRequiresExactPackageAndVersionWithoutReadingPayloads() throws Exception {
        Path dir=Files.createTempDirectory("matrix-profile-");try {
            bundle(dir);
            JSONObject index=Portable.json(dir.resolve("bundle.json"));
            index.put("runtime","large-payload.zip");index.getJSONObject("files").put("large-payload.zip",new JSONObject().put("bytes",999999999).put("sha256","not-read"));
            Portable.json(dir.resolve("bundle.json"),index);
            assertTrue(AdapterEngine.supportsProfile(dir,"VirtualDesktop.Android",10703));
            assertFalse(AdapterEngine.supportsProfile(dir,"VirtualDesktop.Android",10704));
            assertFalse(AdapterEngine.supportsProfile(dir,"other.package",10703));
            Files.write(dir.resolve("recipe.json"),new byte[]{1,2,3});
            assertFalse(AdapterEngine.supportsProfile(dir,"VirtualDesktop.Android",10703));
            assertFalse(AdapterEngine.supportsProfile(dir.resolve("missing"),"VirtualDesktop.Android",10703));
        } finally {Portable.deleteTree(dir);}
    }
    @Test public void inspectionExposesMatrixDetectionAndAndroidLongVersionCode() throws Exception {
        JSONObject input=report("ordinary.app","hash");input.getJSONObject("manifest").put("versionCode",-1).put("versionCodeMajor",2);
        input.getJSONObject("matrix").put("detected",false);
        var ordinary=AdapterEngine.select(input,null);
        assertFalse(ordinary.matrixDetected);assertEquals((2L<<32)|0xffffffffL,ordinary.versionCode);
        input.getJSONObject("matrix").put("detected",true);
        var dependency=AdapterEngine.select(input,null);
        assertTrue(dependency.matrixDetected);assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,dependency.route);
    }

    @Test public void installedTargetLookupStaysStableAcrossVersionsAndMatchesGenericPreparation() throws Exception {
        Path dir=Files.createTempDirectory("matrix-target-");try {
            var bundle=bundle(dir);
            assertEquals("org.picomatrix.bridge.vd",AdapterEngine.targetPackage(dir,"VirtualDesktop.Android"));
            assertTrue(AdapterEngine.supportsProfile(dir,"VirtualDesktop.Android",10703));
            assertFalse(AdapterEngine.supportsProfile(dir,"VirtualDesktop.Android",10704));
            assertEquals("org.picomatrix.bridge.vd",AdapterEngine.targetPackage(dir.toFile(),"VirtualDesktop.Android"));
            String target=AdapterEngine.targetPackage(dir,"another.native.app");
            assertTrue(target.matches("org\\.picomatrix\\.a[0-9a-f]{9}"));
            JSONObject input=report("another.native.app","changed");
            assertEquals(AdapterEngine.Route.GENERIC,AdapterEngine.select(input,bundle).route);
            assertEquals(target,AdapterEngine.targetPackage(dir.resolve("no-bundle"),"another.native.app"));
        } finally {Portable.deleteTree(dir);}
    }

}
