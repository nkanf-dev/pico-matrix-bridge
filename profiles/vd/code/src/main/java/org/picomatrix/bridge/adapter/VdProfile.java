package org.picomatrix.bridge.adapter;

import java.nio.file.Path;
import java.util.*;
import java.util.zip.ZipFile;
import org.json.*;

/** Complete Virtual Desktop adaptation, independently packaged from the Bridge core. */
public final class VdProfile implements ApplicationProfile {
    private final JSONObject recipe,metadata;

    public VdProfile(JSONObject recipe) throws Exception {
        Portable.require(recipe.getInt("schema")==1,"Unsupported VD recipe");
        this.recipe=recipe;this.metadata=recipe.getJSONObject("profile");
        Portable.require("VirtualDesktop.Android".equals(metadata.getString("package")),"Wrong VD profile package");
        Portable.require("research".equals(metadata.getString("status")) &&
            "vd-embedded-v5".equals(metadata.getString("recipe")),"Unexpected VD adaptation contract");
    }

    @Override public JSONObject metadata() {return metadata;}

    @Override public Map<String,byte[]> prepare(Path original,JSONObject inspection,byte[] certificate,String target) throws Exception {
        Portable.require(metadata.getString("package").equals(inspection.getJSONObject("manifest").getString("package")),"VD package differs");
        Portable.require(metadata.getString("outputPackage").equals(target),"VD target differs");
        JSONObject loaderRule=metadata.getJSONObject("managedLoaderIntegrity");
        JSONObject storeRule=recipe.getJSONObject("store"),aotRule=recipe.getJSONObject("aot");
        String loaderEntry=loaderRule.getString("library"),storeEntry=storeRule.getString("entry"),aotEntry=aotRule.getString("entry");
        Portable.require(!loaderEntry.equals(storeEntry)&&!loaderEntry.equals(aotEntry)&&!storeEntry.equals(aotEntry),"Duplicate VD target");
        try(ZipFile apk=new ZipFile(original.toFile())) {
            byte[] loader=AdapterEngine.entry(apk,loaderEntry,16*1024*1024);
            JSONObject nativeRule=metadata.getJSONObject("libraries").getJSONObject(loaderEntry);
            Portable.require(Portable.sha(loader).equals(nativeRule.getString("sha256")),"VD loader differs");
            byte[] routed=ApkRewriter.route(loader,nativeRule.getInt("replacements"),target);
            byte[] store=IntegrityRecipe.store(AdapterEngine.entry(apk,storeEntry,32*1024*1024),storeRule,certificate,routed);
            byte[] aot=IntegrityRecipe.aot(AdapterEngine.entry(apk,aotEntry,16*1024*1024),aotRule,certificate);
            Map<String,byte[]> replacements=new LinkedHashMap<>();replacements.put(storeEntry,store);replacements.put(aotEntry,aot);
            return Collections.unmodifiableMap(replacements);
        }
    }

    @Override public void verify(Path original,Path unsigned,Map<String,byte[]> replacements) throws Exception {
        Portable.require(replacements.size()==2,"VD integrity targets missing");
        try(ZipFile apk=new ZipFile(unsigned.toFile())) {
            for(var replacement:replacements.entrySet())
                Portable.require(Arrays.equals(replacement.getValue(),AdapterEngine.entry(apk,replacement.getKey(),48*1024*1024)),
                    "Prepared VD integrity target differs: "+replacement.getKey());
            JSONObject rule=metadata.getJSONObject("managedLoaderIntegrity");String name=rule.getString("library");
            byte[] loader=AdapterEngine.entry(apk,name,16*1024*1024);
            try(ZipFile source=new ZipFile(original.toFile())) {
                byte[] expected=ApkRewriter.route(AdapterEngine.entry(source,name,16*1024*1024),
                    metadata.getJSONObject("libraries").getJSONObject(name).getInt("replacements"),metadata.getString("outputPackage"));
                Portable.require(Arrays.equals(loader,expected),"VD managed loader binding differs");
            }
        }
    }
}
