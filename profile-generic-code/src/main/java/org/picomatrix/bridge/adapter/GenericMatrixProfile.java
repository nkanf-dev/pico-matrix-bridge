package org.picomatrix.bridge.adapter;

import java.nio.file.Path;
import java.util.*;
import java.util.zip.ZipFile;
import org.json.*;

/** Independently signed profile for the checked native Matrix integration. */
public final class GenericMatrixProfile implements ApplicationProfile {
    private final JSONObject recipe;

    public GenericMatrixProfile(JSONObject recipe) {
        Portable.require(recipe.getInt("schema")==1 && "generic".equals(recipe.getJSONObject("profile").getString("profileKey")),
            "Wrong generic profile");
        this.recipe=recipe;
    }

    @Override public JSONObject metadata() {return recipe.getJSONObject("profile");}
    @Override public JSONObject select(JSONObject inspection) throws Exception {
        JSONObject matrix=inspection.getJSONObject("matrix");
        if(!matrix.getBoolean("detected") || inspection.getJSONObject("managedRuntime").getBoolean("requiresManagedCodeReview") ||
            matrix.getJSONArray("dexReferences").length()!=0)return null;
        JSONObject approved=recipe.getJSONObject("libraries"),libraries=new JSONObject();
        JSONArray actual=matrix.getJSONArray("libraries");
        for(int i=0;i<actual.length();i++) {
            JSONObject library=actual.getJSONObject(i);String entry=library.getString("entry");
            if(!approved.has(entry)||!approved.getJSONObject(entry).getString("sha256").equals(library.getString("sha256")))return null;
            libraries.put(entry,approved.getJSONObject(entry));
        }
        if(libraries.length()==0)return null;
        Set<String> ids=new HashSet<>(),names=new HashSet<>();JSONArray selectors=recipe.getJSONArray("appIdMetadataNames");
        for(int i=0;i<selectors.length();i++)names.add(selectors.getString(i));
        JSONArray metadata=inspection.getJSONObject("manifest").getJSONArray("metadata");
        for(int i=0;i<metadata.length();i++) {
            JSONObject item=metadata.getJSONObject(i);
            if(names.contains(item.optString("name"))) {
                String value=item.optString("value");if(!value.matches("[A-Za-z0-9_-]{8,128}"))return null;ids.add(value);
            }
        }
        if(ids.size()!=1)return null;
        String pkg=inspection.getJSONObject("manifest").getString("package");
        return new JSONObject().put("id","generic-native-matrix-v1").put("status","research")
            .put("package",pkg).put("outputPackage",AdapterEngine.genericTargetPackage(pkg))
            .put("inputSha256",inspection.getJSONObject("source").getString("sha256"))
            .put("appId",ids.iterator().next()).put("libraries",libraries).put("account",recipe.getJSONObject("account"));
    }

    @Override public Map<String,byte[]> prepare(Path original,JSONObject inspection,byte[] certificate,String target) throws Exception {
        JSONObject selected=select(inspection);
        Portable.require(selected!=null && target.equals(selected.getString("outputPackage")),"Generic profile input changed");
        return Map.of();
    }

    @Override public void verify(Path original,Path unsigned,Map<String,byte[]> replacements) throws Exception {
        Portable.require(replacements.isEmpty(),"Unexpected generic replacement");
        JSONObject approved=recipe.getJSONObject("libraries");int checked=0;
        String target=AdapterEngine.genericTargetPackage(ApkInspector.inspect(original).getJSONObject("manifest").getString("package"));
        try(ZipFile before=new ZipFile(original.toFile());ZipFile after=new ZipFile(unsigned.toFile())) {
            for(String entry:approved.keySet())if(before.getEntry(entry)!=null) {
                JSONObject rule=approved.getJSONObject(entry);
                byte[] originalBytes=AdapterEngine.entry(before,entry,16*1024*1024);
                if(!Portable.sha(originalBytes).equals(rule.getString("sha256")))continue;
                byte[] routed=ApkRewriter.route(originalBytes,rule.getInt("replacements"),target);
                Portable.require(Arrays.equals(routed,AdapterEngine.entry(after,entry,16*1024*1024)),"Generic native route differs");
                checked++;
            }
        }
        Portable.require(checked>0,"Generic native route missing");
    }
}
