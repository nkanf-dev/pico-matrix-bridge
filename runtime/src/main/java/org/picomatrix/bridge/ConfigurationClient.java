package org.picomatrix.bridge;

import android.content.Context;
import org.picomatrix.bridge.protocol.MatrixContract;
import org.picomatrix.bridge.protocol.Wire;
import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** Only the observed, account-free configuration endpoint; never a general proxy. */
public final class ConfigurationClient {
    private static final String ENDPOINT="https://platform-us.picovr.com/configuration/v1/module/get";
    private static volatile Method signer;

    public static void initialize(Context client) throws Exception {
        Context bridge=client;
        JSONObject profile;
        try(InputStream in=bridge.getAssets().open("matrix-runtime-profile.json")) {
            profile=new JSONObject(new String(read(in,512*1024),StandardCharsets.UTF_8));
        }
        if(!MatrixContract.SOURCE_SHA256.equals(profile.getJSONObject("source").getString("sha256")))
            throw new IllegalStateException("runtime profile mismatch");
        JSONObject entry=profile.getJSONObject("entrypoints").getJSONObject("requestSigner");
        signer=Class.forName(entry.getString("class"),true,ConfigurationClient.class.getClassLoader())
            .getDeclaredMethod(entry.getString("method"),boolean.class,String.class,String.class,String.class,byte[].class);
    }
    public static byte[] sign(boolean get,String appId,String url,byte[] body) throws Exception {
        Method method=signer;
        if(method==null) throw new IllegalStateException("signer unavailable");
        return (byte[])method.invoke(null,get,appId,"",url,body);
    }
    static byte[] read(InputStream in,int max) throws IOException {
        ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int count;
        while((count=in.read(buffer))!=-1) {
            if(count>max-out.size()) throw new IOException("response too large");
            out.write(buffer,0,count);
        }
        return out.toByteArray();
    }
    public static byte[] fetch(byte[] request) throws Exception {
        Wire envelope=Wire.parse(request);
        Wire body=Wire.parse(envelope.bytes(MatrixContract.Request.body));
        Wire config=Wire.parse(body.bytes(MatrixContract.RequestBody_getConfigurationRequest));
        String appId=config.string(MatrixContract.GetConfigurationRequest.appId);
        if(!appId.matches("[A-Za-z0-9_-]{1,64}")) throw new IllegalArgumentException("invalid application ID");
        List<String> modules=config.strings(MatrixContract.GetConfigurationRequest.modules);
        if(modules.isEmpty() || modules.size()>32) throw new IllegalArgumentException("invalid configuration modules");
        for(String module:modules) if(!module.matches("[A-Za-z0-9_.-]{1,128}")) throw new IllegalArgumentException("invalid module");
        byte[] payload=new JSONObject().put("modules",new JSONArray(modules)).toString().getBytes(StandardCharsets.UTF_8);
        String auth=new String(sign(false,appId,ENDPOINT,payload),StandardCharsets.UTF_8);
        if(auth.isEmpty() || auth.contains("\r") || auth.contains("\n")) throw new IOException("invalid signing result");
        HttpURLConnection connection=(HttpURLConnection)new URL(ENDPOINT).openConnection();
        try {
            connection.setInstanceFollowRedirects(false);connection.setConnectTimeout(4000);connection.setReadTimeout(4000);
            connection.setRequestMethod("POST");connection.setRequestProperty("Content-Type","application/json");
            connection.setRequestProperty("User-Agent","pico_pui");connection.setRequestProperty("Agw-Auth",auth);
            connection.setDoOutput(true);connection.setFixedLengthStreamingMode(payload.length);
            try(OutputStream out=connection.getOutputStream()) { out.write(payload); }
            int status=connection.getResponseCode();
            if(status!=200) throw new IOException("configuration HTTP "+status);
            JSONObject response;
            try(InputStream in=connection.getInputStream()) { response=new JSONObject(new String(read(in,256*1024),StandardCharsets.UTF_8)); }
            if(response.getInt("code")!=0) throw new IOException("configuration rejected, code="+response.getInt("code"));
            JSONObject values=response.getJSONObject("data").getJSONObject("configurations");
            Wire.Builder result=new Wire.Builder();
            List<String> keys=new ArrayList<>();Iterator<String> iterator=values.keys();while(iterator.hasNext()) keys.add(iterator.next());Collections.sort(keys);
            for(String key:keys) {
                Object value=values.get(key);
                if(!(value instanceof String)) throw new IOException("unexpected configuration value");
                result.bytes(MatrixContract.GetConfigurationResponse.configurations,new Wire.Builder().string(1,key).string(2,(String)value).build());
            }
            return new Wire.Builder().bytes(MatrixContract.ResponseBody_getConfigurationResponse,result.build()).build();
        } finally { connection.disconnect(); }
    }
    private ConfigurationClient() {}
}
