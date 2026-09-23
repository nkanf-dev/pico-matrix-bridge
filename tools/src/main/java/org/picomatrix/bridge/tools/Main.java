package org.picomatrix.bridge.tools;
import org.picomatrix.bridge.adapter.*;

import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.*;
import java.util.*;
import java.util.zip.*;
import org.json.*;
import org.jf.dexlib2.*;
import org.jf.dexlib2.dexbacked.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

public final class Main {
    static final String MATRIX=ApkInspector.MATRIX;
    static byte[] bounded(InputStream input,int limit) throws IOException { return ApkInspector.bounded(input,limit); }
    static boolean contains(byte[] a,byte[] b) { return ApkInspector.contains(a,b); }
    static boolean nativeReferences(InputStream input) throws IOException { return ApkInspector.nativeReferences(input); }
    public static JSONObject inspect(Path path) throws Exception { return ApkInspector.inspect(path); }
    private static void writeReport(Path source,Path output,JSONObject result) throws Exception {
        if (source.equals(output.normalize()) || (Files.exists(output) && Files.isSameFile(source,output))) throw new IllegalArgumentException("output must not replace source");
        Files.createDirectories(output.getParent());
        Path staging=Files.createTempFile(output.getParent(),output.getFileName()+"-", ".part");
        try {
            Files.writeString(staging,result.toString(2)+"\n",StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(staging,output,StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally { Files.deleteIfExists(staging); }
    }
    public static void main(String[] args) throws Exception {
        if((args.length==7||args.length==8) && args[0].equals("prepare-portable")) {
            Path recipe=args.length==8?Path.of(args[7]):Path.of(args[2],"vd-recipe.json");
            ApplicationProfile profile=Files.isRegularFile(recipe)?new VdProfile(new JSONObject(Files.readString(recipe))):null;
            AdapterEngine.Result result=AdapterEngine.prepare(Path.of(args[1]),Path.of(args[2]),Path.of(args[3]),Files.readAllBytes(Path.of(args[4])),args[5],args[6],profile);
            JSONObject json=new JSONObject().put("output",result.output.toString()).put("requiresSigning",result.requiresSigning).put("inputSha256",result.inputSha256)
                .put("outputSha256",result.outputSha256).put("profileId",result.profileId).put("appId",result.appId).put("package",result.packageName).put("targetSignerSha256",result.targetSignerSha256);
            Files.writeString(Path.of(args[3]+".json"),json.toString(2)+"\n");System.out.println(json);return;
        }
        if(args.length==5 && args[0].equals("apply-vd-recipe")) {
            JSONObject recipe=new JSONObject(Files.readString(Path.of(args[2]))),profile=recipe.getJSONObject("profile");byte[] cert=Files.readAllBytes(Path.of(args[3]));Path out=Path.of(args[4]);Files.createDirectories(out);
            try(ZipFile zip=new ZipFile(args[1])) {
                JSONObject loaderRule=profile.getJSONObject("managedLoaderIntegrity"),storeRule=recipe.getJSONObject("store"),aotRule=recipe.getJSONObject("aot");
                byte[] loader;try(InputStream in=zip.getInputStream(zip.getEntry(loaderRule.getString("library")))){loader=bounded(in,16*1024*1024);}
                byte[] routed=ResearchAdapter.route(loader,1,profile.getString("outputPackage"));Files.write(out.resolve("loader.so"),routed);
                try(InputStream in=zip.getInputStream(zip.getEntry(storeRule.getString("entry")))){Files.write(out.resolve("managed-store.so"),IntegrityRecipe.store(bounded(in,32*1024*1024),storeRule,cert,routed));}
                try(InputStream in=zip.getInputStream(zip.getEntry(aotRule.getString("entry")))){Files.write(out.resolve("mobile-aot.so"),IntegrityRecipe.aot(bounded(in,16*1024*1024),aotRule,cert));}
            }
            System.out.println(new JSONObject().put("output",out.toString()));return;
        }
        if(args.length==6 && args[0].equals("prepare-embedded-dex")) {
            System.out.println(EmbeddedDex.prepare(Path.of(args[1]),Path.of(args[2]),Path.of(args[3]),Path.of(args[4]),Path.of(args[5])));return;
        }
        if(args.length==5 && args[0].equals("adapt-vd-research")) {
            JSONObject result=ResearchAdapter.adapt(Path.of(args[1]).toRealPath(),Path.of(args[2]).toAbsolutePath(),
                new JSONObject(Files.readString(Path.of(args[3]))),new JSONObject(Files.readString(Path.of(args[4]))));
            Files.writeString(Path.of(args[2]+".json"),result.toString(2)+"\n");System.out.println(result);return;
        }
        if(args.length==4 && args[0].equals("preflight-research")) {
            Path input=Path.of(args[1]).toRealPath(), output=Path.of(args[2]).toAbsolutePath();
            JSONObject result=ResearchAdapter.admission(inspect(input),new JSONObject(Files.readString(Path.of(args[3]))));
            writeReport(input,output,result);System.out.println(result);return;
        }
        if(args.length==4 && args[0].equals("adapt-research")) {
            JSONObject result=ResearchAdapter.adapt(Path.of(args[1]).toRealPath(),Path.of(args[2]).toAbsolutePath(),new JSONObject(Files.readString(Path.of(args[3]))));
            Files.writeString(Path.of(args[2]+".json"),result.toString(2)+"\n");System.out.println(result);return;
        }
        if(args.length!=3 || !args[0].equals("inspect")) throw new IllegalArgumentException("Usage: matrix-tools inspect input.apk output.json | preflight-research input.apk report.json profile.json | adapt-research input.apk output.apk profile.json");
        Path source=Path.of(args[1]).toRealPath(), output=Path.of(args[2]).toAbsolutePath();
        JSONObject result=inspect(source);writeReport(source,output,result);
        System.out.println(new JSONObject().put("output",output.toString()).put("classes",result.getInt("classCount")).put("matrix",result.getJSONObject("matrix").getBoolean("detected")).put("messages",result.getJSONObject("contracts").getInt("messageCount")));
    }
}
