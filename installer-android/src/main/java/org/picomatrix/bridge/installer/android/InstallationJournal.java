package org.picomatrix.bridge.installer.android;

import android.content.Context;
import android.util.AtomicFile;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** Non-secret installation receipts survive Activity/process recreation. */
final class InstallationJournal {
    static final Object LOCK=new Object();
    private final AtomicFile file;
    InstallationJournal(Context c) { file=new AtomicFile(new File(c.getNoBackupFilesDir(),"matrix-installations.json")); }
    List<JSONObject> read() throws Exception {
        synchronized(LOCK) {
            if(!file.getBaseFile().exists() && !new File(file.getBaseFile()+".bak").exists()) return new ArrayList<>();
            byte[] data;
            try(InputStream in=file.openRead();ByteArrayOutputStream out=new ByteArrayOutputStream()) {
                byte[] b=new byte[4096];int n;while((n=in.read(b))!=-1) {if(out.size()+n>128*1024) throw new IOException("Installation journal too large");out.write(b,0,n);}data=out.toByteArray();
            }
            JSONObject root=new JSONObject(new String(data,StandardCharsets.UTF_8));
            if(root.getInt("schema")!=1) throw new IOException("Unknown installation journal");
            JSONArray entries=root.getJSONArray("entries");List<JSONObject> result=new ArrayList<>();
            for(int i=0;i<entries.length();i++) result.add(entries.getJSONObject(i));return result;
        }
    }
    void save(JSONObject record) throws Exception {
        synchronized(LOCK) {
            List<JSONObject> records=read();records.removeIf(r->r.optString("id").equals(record.optString("id")));
            records.add(record);
            while(records.size()>32) {
                int remove=-1;for(int i=0;i<records.size()-1;i++) if(status(records.get(i)).terminal()) {remove=i;break;}
                if(remove<0) throw new IOException("Too many pending installations");records.remove(remove);
            }
            byte[] bytes=new JSONObject().put("schema",1).put("entries",new JSONArray(records)).toString().getBytes(StandardCharsets.UTF_8);
            FileOutputStream stream=file.startWrite();
            try {stream.write(bytes);file.finishWrite(stream);} catch(Exception e) {file.failWrite(stream);throw e;}
        }
    }
    JSONObject get(String id) throws Exception { for(JSONObject r:read()) if(r.getString("id").equals(id)) return r;return null; }
    static InstallationStatus status(JSONObject r) { return new InstallationStatus(r.optString("id"),r.optString("stage"),r.optString("package"),r.optString("code")); }
}
