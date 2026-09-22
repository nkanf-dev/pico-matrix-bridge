package org.picomatrix.bridge.tools;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;
import org.json.*;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.dexbacked.DexBackedDexFile;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.writer.io.MemoryDataStore;
import org.jf.dexlib2.writer.pool.DexPool;

/** Keeps bootstrap classes separate from all application/vendor dependencies. */
final class EmbeddedDex {
    static final Set<String> REQUIRED_BOOTSTRAP=Set.of(
        "Lorg/picomatrix/bridge/embedded/EmbeddedRuntime;",
        "Lorg/picomatrix/bridge/embedded/LaunchActivity;",
        "Lorg/picomatrix/bridge/embedded/ProvisioningProvider;",
        "Lcom/bytedance/pico/matrix/platform/PlatformSDKDriverLoader;",
        "Lcom/bytedance/pico/matrix/server/ServerBrokerJni;");
    static void requireBootstrap(Set<String> types) throws IOException {
        Set<String> missing=new TreeSet<>(REQUIRED_BOOTSTRAP);missing.removeAll(types);
        if(!missing.isEmpty()) throw new IOException("Missing application-loader entrypoints: "+missing);
    }
    private static boolean owned(String type) {
        return type.startsWith("Lorg/picomatrix/bridge/embedded/") || type.equals("Lcom/bytedance/pico/matrix/platform/PlatformSDKDriverLoader;") || type.equals("Lcom/bytedance/pico/matrix/server/ServerBrokerJni;");
    }
    static byte[] encode(Collection<? extends ClassDef> classes) throws IOException {
        DexPool pool=new DexPool(Opcodes.forApi(29));for(ClassDef c:classes) pool.internClass(c);
        MemoryDataStore out=new MemoryDataStore();pool.writeTo(out);return Arrays.copyOf(out.getBuffer(),out.getSize());
    }
    static List<DexBackedDexFile> read(Path apk) throws IOException {
        List<DexBackedDexFile> result=new ArrayList<>();
        try(ZipFile zip=new ZipFile(apk.toFile())) {
            for(ZipEntry entry:Collections.list(zip.entries())) if(entry.getName().matches("classes[0-9]*\\.dex"))
                try(InputStream in=zip.getInputStream(entry)) {result.add(new DexBackedDexFile(Opcodes.forApi(29),Main.bounded(in,128*1024*1024)));}
        }
        return result;
    }
    static Set<String> types(Path apk) throws IOException {
        Set<String> result=new HashSet<>();for(var dex:read(apk)) for(ClassDef c:dex.getClasses())
            if(!result.add(c.getType())) throw new IOException("Duplicate input class: "+c.getType());
        return result;
    }
    static JSONObject prepare(Path bootstrap,Path runtime,Path vendor,Path client,Path out) throws Exception {
        Files.createDirectories(out);Set<String> clientTypes=types(client),runtimeTypes=types(runtime);
        List<ClassDef> bridge=new ArrayList<>();
        for(var dex:read(bootstrap)) for(ClassDef c:dex.getClasses()) if(owned(c.getType())) {
            if(clientTypes.contains(c.getType())) throw new IOException("Bootstrap collides with target class: "+c.getType());bridge.add(c);
        }
        Set<String> exposed=new HashSet<>();for(ClassDef c:bridge) exposed.add(c.getType());
        requireBootstrap(exposed);
        Files.write(out.resolve("bootstrap.dex"),encode(bridge));
        Set<String> expected=Set.of("Lcom/bytedance/pico/matrix/platform/PlatformSDKDriverLoader;","Lcom/bytedance/pico/matrix/server/ServerBrokerJni;");
        Set<String> replaced=new TreeSet<>();List<String> entries=new ArrayList<>();int index=0,count=0;
        for(var dex:read(vendor)) {
            List<ClassDef> retained=new ArrayList<>();
            for(ClassDef c:dex.getClasses()) {
                if(runtimeTypes.contains(c.getType())) {
                    if(!expected.contains(c.getType())) throw new IOException("Unreviewed runtime collision: "+c.getType());replaced.add(c.getType());
                } else retained.add(c);
            }
            String name="vendor-"+(++index)+".dex";Files.write(out.resolve(name),encode(retained));entries.add(name);count+=retained.size();
        }
        if(!replaced.equals(expected)) throw new IOException("Vendor overrides differ from contract");
        JSONObject result=new JSONObject().put("bootstrapClasses",bridge.size()).put("vendorClasses",count)
            .put("vendorDex",entries).put("overriddenClasses",replaced).put("applicationCollisions",0);
        Files.writeString(out.resolve("dex-evidence.json"),result.toString(2)+"\n");return result;
    }
}
