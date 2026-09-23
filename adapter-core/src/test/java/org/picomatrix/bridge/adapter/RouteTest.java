package org.picomatrix.bridge.adapter;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.nio.file.*;
import java.util.*;

public class RouteTest {
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
        JSONObject manifest=new JSONObject().put("schema",1).put("bootstrap","runtime.zip").put("runtime","runtime.zip")
            .put("matrixProfile","runtime.zip").put("files",files);
        Portable.json(dir.resolve("bundle.json"),manifest);return new AdapterEngine.Bundle(dir);
    }
    private ApplicationProfile candidate(String id,String matcher,int priority,String inputHash,long version) {
        return new ApplicationProfile() {
            @Override public JSONObject metadata() {
                JSONObject value=new JSONObject().put("id",id).put("packageMatcher",matcher).put("package",matcher)
                    .put("outputPackage","example.output").put("priority",priority).put("appId","client123");
                if(inputHash!=null)value.put("inputSha256",inputHash).put("versionCode",version);
                return value;
            }
            @Override public JSONObject select(JSONObject inspection) {
                return metadata().put("package",inspection.getJSONObject("manifest").getString("package"));
            }
            @Override public Map<String,byte[]> prepare(Path original,JSONObject inspection,byte[] certificate,String target) {return Map.of();}
            @Override public void verify(Path original,Path unsigned,Map<String,byte[]> replacements) {}
        };
    }
    private JSONObject report(String pkg,String hash) {
        return new JSONObject().put("manifest",new JSONObject().put("package",pkg).put("versionCode",10703)
                .put("metadata",new JSONArray().put(new JSONObject().put("name","app_id").put("value","client123"))))
            .put("source",new JSONObject().put("sha256",hash))
            .put("managedRuntime",new JSONObject().put("requiresManagedCodeReview",false))
            .put("matrix",new JSONObject().put("detected",true).put("dexReferences",new JSONArray())
                .put("libraries",new JSONArray()));
    }
    @Test public void aMatchingImplementationOwnsAttemptsAcrossAppVersions() throws Exception {
        Path dir=Files.createTempDirectory("matrix-route-");try {
            var bundle=bundle(dir);var profile=profile();
            assertTrue(AdapterEngine.select(report("example.target","original"),bundle,List.of(profile)).profileExact);
            assertEquals(AdapterEngine.Route.PROFILE,AdapterEngine.select(report("example.target","changed"),bundle,List.of(profile)).route);
            JSONObject newer=report("example.target","changed");newer.getJSONObject("manifest").put("versionCode",10704);
            assertFalse(AdapterEngine.select(newer,bundle,List.of(profile)).profileExact);
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(newer,null,List.of()).route);
            assertEquals(AdapterEngine.Route.ANALYSIS_REQUIRED,AdapterEngine.select(report("another.native.app","changed"),bundle,List.of(profile)).route);
            assertTrue(AdapterEngine.canAttemptProfile(profile,"example.target"));
            assertTrue(AdapterEngine.supportsProfile(profile,"example.target",10703));
            assertFalse(AdapterEngine.supportsProfile(profile,"example.target",10704));
        } finally {Portable.deleteTree(dir);}
    }
    @Test public void selectionRanksPriorityPackageAndVersionWithoutProfileNames() throws Exception {
        JSONObject input=report("example.target","original");
        var generic=candidate("wildcard","*",0,null,0);
        var packageFallback=candidate("package-fallback","example.target",10,null,0);
        var exactVersion=candidate("versioned","example.target",10,"original",10703);
        var higherPriority=candidate("higher","example.target",20,"older",10702);
        assertEquals("higher",AdapterEngine.select(input,null,List.of(generic,exactVersion,higherPriority)).profileId);
        assertEquals("versioned",AdapterEngine.select(input,null,List.of(generic,packageFallback,exactVersion)).profileId);
        assertEquals("versioned",AdapterEngine.select(report("example.target","changed"),null,
            List.of(generic,exactVersion)).profileId);
        assertEquals("wildcard",AdapterEngine.select(report("other.app","changed"),null,List.of(generic)).profileId);
        assertFalse(AdapterEngine.select(report("other.app","changed"),null,List.of(generic)).profileExact);
        assertEquals("package-fallback",AdapterEngine.select(input,null,
            List.of(candidate("same-score","example.target",10,null,0),packageFallback)).profileId);
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
        var ordinary=AdapterEngine.select(input,null,List.of());
        assertFalse(ordinary.matrixDetected);assertEquals((2L<<32)|0xffffffffL,ordinary.versionCode);
        input.getJSONObject("matrix").put("detected",true);
        var dependency=AdapterEngine.select(input,null,List.of());
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
