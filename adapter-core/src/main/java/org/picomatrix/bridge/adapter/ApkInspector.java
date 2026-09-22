package org.picomatrix.bridge.adapter;

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

public final class ApkInspector {
    public static final String MATRIX = "com.bytedance.pico.matrix";
    public static boolean matrixReference(String s) { return s.contains(MATRIX) || s.contains("com/bytedance/pico/matrix"); }
    public static byte[] bounded(InputStream input, int limit) throws IOException {
        byte[] result = Portable.read(input,limit);
        if (result.length > limit) throw new IOException("entry exceeds inspection limit");
        return result;
    }
    public static boolean contains(byte[] haystack, byte[] needle) {
        outer: for (int i=0; i<=haystack.length-needle.length; i++) {
            for (int j=0; j<needle.length; j++) if (haystack[i+j]!=needle[j]) continue outer;
            return true;
        }
        return false;
    }
    public static boolean nativeReferences(InputStream in) throws IOException {
        byte[] needle = MATRIX.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] buffer = new byte[65536+needle.length]; int tail=0, count;long consumed=0;
        while ((count=in.read(buffer,tail,65536))!=-1) {
            consumed+=count;
            if(consumed>1024L*1024*1024) throw new IOException("native entry exceeds inspection limit");
            int total=tail+count;
            if (contains(Arrays.copyOf(buffer,total),needle)) return true;
            tail=Math.min(needle.length-1,total); System.arraycopy(buffer,total-tail,buffer,0,tail);
        }
        return false;
    }
    public static JSONObject inspect(Path apk) throws Exception {
        BasicFileAttributes before=Files.readAttributes(apk,BasicFileAttributes.class);
        MessageDigest digest=MessageDigest.getInstance("SHA-256");
        try (InputStream in=new DigestInputStream(Files.newInputStream(apk),digest)) { byte[] buffer=new byte[65536];while(in.read(buffer)!=-1) {} }
        Contracts contracts=new Contracts(); JSONArray dex=new JSONArray(), refs=new JSONArray(), nativeRefs=new JSONArray(), libraries=new JSONArray(), managedStores=new JSONArray();
        JSONObject entrypoints=new JSONObject();
        JSONObject manifest;
        Set<String> entryNames=new HashSet<>(); int classCount=0;
        try (ZipFile zip=new ZipFile(apk.toFile())) {
            ZipEntry mf=zip.getEntry("AndroidManifest.xml");
            if (mf==null) throw new IOException("APK has no manifest");
            try(InputStream in=zip.getInputStream(mf)) { manifest=new BinaryManifest(bounded(in,8*1024*1024)).read(); }
            for(ZipEntry entry:Collections.list(zip.entries())) {
                if (!entryNames.add(entry.getName())) throw new IOException("duplicate APK entry: "+entry.getName());
                if(entry.getName().matches("classes[0-9]*\\.dex")) {
                    byte[] bytes;
                    try(InputStream in=zip.getInputStream(entry)) { bytes=bounded(in,128*1024*1024); }
                    DexBackedDexFile file=new DexBackedDexFile(Opcodes.getDefault(),bytes);
                    // Indexed strings also cover static field constants and type-only references.
                    for(StringReference sr:file.getStringReferences()) {
                        if(matrixReference(sr.getString())) refs.put(new JSONObject().put("dex",entry.getName()).put("kind","string-pool").put("literal",sr.getString()));
                    }
                    int n=0;
                    for(ClassDef cls:file.getClasses()) {
                        n++; contracts.accept(cls);
                        for(Method method:cls.getMethods()) {
                            if(method.getImplementation()==null) continue;
                            Set<String> values=new TreeSet<>();
                            for(Instruction insn:method.getImplementation().getInstructions()) {
                                if(insn instanceof ReferenceInstruction ri) {
                                    Reference reference=ri.getReference();
                                    String value = reference instanceof StringReference sr ? sr.getString() : reference.toString();
                                    if(matrixReference(value)) values.add(value);
                                    if(cls.getType().equals("Lcom/bytedance/pico/matrix/server/ServerBrokerJni;") && method.getName().equals("getSignHeaders") && reference instanceof MethodReference mr && mr.getReturnType().equals("[B") && mr.getParameterTypes().toString().equals("[Z, Ljava/lang/String;, Ljava/lang/String;, Ljava/lang/String;, [B]")) {
                                        JSONObject signer=new JSONObject().put("class",mr.getDefiningClass().substring(1,mr.getDefiningClass().length()-1).replace('/','.')).put("method",mr.getName());
                                        if(entrypoints.has("requestSigner") && !entrypoints.getJSONObject("requestSigner").toString().equals(signer.toString())) throw new IOException("ambiguous signer entrypoint");
                                        entrypoints.put("requestSigner",signer);
                                    }
                                }
                            }
                            for(String value:values) refs.put(new JSONObject().put("dex",entry.getName()).put("class",cls.getType()).put("method",method.getName()).put("literal",value));
                        }
                    }
                    classCount+=n; dex.put(new JSONObject().put("entry",entry.getName()).put("classes",n).put("bytes",bytes.length));
                } else if(entry.getName().endsWith(".dll") || entry.getName().endsWith("/global-metadata.dat")) {
                    managedStores.put(entry.getName());
                } else if(entry.getName().startsWith("lib/") && entry.getName().endsWith(".so")) {
                    if(entry.getName().matches("lib/[^/]+/libassemblies\\.[^/]+\\.blob\\.so") || entry.getName().endsWith("/libassembly-store.so") || entry.getName().endsWith("/libil2cpp.so") || entry.getName().contains("/libmonosgen"))
                        managedStores.put(entry.getName());
                    if(entry.getSize()<0 || entry.getSize()>1024L*1024*1024) throw new IOException("native entry exceeds inspection limit");
                    boolean referenced;
                    try(InputStream in=zip.getInputStream(entry)) { referenced=nativeReferences(in); }
                    if(referenced) {
                        nativeRefs.put(entry.getName());
                        MessageDigest hash=MessageDigest.getInstance("SHA-256");
                        try(InputStream in=new DigestInputStream(zip.getInputStream(entry),hash)) {
                            byte[] chunk=new byte[65536];long total=0;int count;
                            while((count=in.read(chunk))!=-1) { total+=count;if(total>1024L*1024*1024) throw new IOException("native entry exceeds inspection limit"); }
                        }
                        libraries.put(new JSONObject().put("entry",entry.getName()).put("bytes",entry.getSize()).put("sha256",Portable.hex(hash.digest())));
                    }
                }
            }
        }
        BasicFileAttributes after=Files.readAttributes(apk,BasicFileAttributes.class);
        if(before.size()!=after.size() || !before.lastModifiedTime().equals(after.lastModifiedTime()) || !Objects.equals(before.fileKey(),after.fileKey()))
            throw new IOException("source changed during inspection");
        return new JSONObject().put("schemaVersion",1).put("source",new JSONObject().put("name",apk.getFileName()).put("bytes",Files.size(apk)).put("sha256",Portable.hex(digest.digest())))
            .put("manifest",manifest).put("dex",dex).put("classCount",classCount).put("entrypoints",entrypoints).put("matrix",new JSONObject().put("detected",refs.length()!=0||nativeRefs.length()!=0).put("dexReferences",refs).put("nativeReferences",nativeRefs).put("libraries",libraries))
            .put("managedRuntime",new JSONObject().put("assemblyStores",managedStores).put("requiresManagedCodeReview",managedStores.length()!=0))
            .put("contracts",contracts.json()).put("interpretation","Static references and declarations only; this is not runtime compatibility evidence.");
    }
}
