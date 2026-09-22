package org.picomatrix.bridge.installer.android;

import android.content.Context;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Installs hash-pinned build assets, without fetching executable code from a server. */
public final class AssetBundle {
    public static synchronized File open(Context context,String assetDirectory) throws Exception {
        if(!assetDirectory.matches("[a-zA-Z0-9_-]+")) throw new IllegalArgumentException("Invalid asset directory");
        byte[] manifest;
        try(InputStream in=context.getAssets().open(assetDirectory+"/bundle.json")) {manifest=read(in,256*1024);}
        JSONObject description=new JSONObject(new String(manifest,StandardCharsets.UTF_8));
        if(description.getInt("schema")!=1) throw new IOException("Unknown compatibility bundle");
        File destination=new File(context.getFilesDir(),"matrix-bundles/"+LocalSigner.hash(manifest));
        if(!destination.isDirectory() && !destination.mkdirs()) throw new IOException("Cannot prepare compatibility bundle");
        JSONObject files=description.getJSONObject("files");long total=0;
        List<String> names=new ArrayList<>();files.keys().forEachRemaining(names::add);Collections.sort(names);
        for(String name:names) {
            if(name.startsWith("/") || name.contains("\\") || Arrays.asList(name.split("/",-1)).stream().anyMatch(p->p.isEmpty()||p.equals(".")||p.equals("..")))
                throw new IOException("Invalid bundle entry");
            JSONObject identity=files.getJSONObject(name);long size=identity.getLong("bytes");
            String expected=identity.getString("sha256");total+=size;
            if(size<=0 || size>96L*1024*1024 || total>128L*1024*1024 || !expected.matches("[a-f0-9]{64}")) throw new IOException("Invalid bundle identity");
            File file=new File(destination,name);
            if(file.isFile() && file.length()==size && expected.equals(LocalSigner.hash(file))) continue;
            if(!file.getParentFile().isDirectory() && !file.getParentFile().mkdirs()) throw new IOException("Cannot prepare bundle entry");
            File part=new File(file.getParentFile(),file.getName()+".part");
            try {
                try(InputStream in=context.getAssets().open(assetDirectory+"/"+name);FileOutputStream out=new FileOutputStream(part)) {
                    byte[] buffer=new byte[65536];long received=0;int n;
                    while((n=in.read(buffer))!=-1) {received+=n;if(received>size) throw new IOException("Bundle entry too large");out.write(buffer,0,n);}out.getFD().sync();
                }
                if(part.length()!=size || !expected.equals(LocalSigner.hash(part))) throw new IOException("Bundle hash mismatch");
                Files.move(part.toPath(),file.toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
            } finally {part.delete();}
        }
        File part=new File(destination,"bundle.json.part");
        try {
            try(FileOutputStream out=new FileOutputStream(part)) {out.write(manifest);out.getFD().sync();}
            Files.move(part.toPath(),new File(destination,"bundle.json").toPath(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
        } finally {part.delete();}
        return destination;
    }
    private static byte[] read(InputStream in,int limit) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[8192];int n;
        while((n=in.read(b))!=-1) {if(out.size()+n>limit) throw new IOException("Bundle manifest too large");out.write(b,0,n);}return out.toByteArray();
    }
    private AssetBundle() {}
}
