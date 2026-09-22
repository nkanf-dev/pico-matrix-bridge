package org.picomatrix.bridge.account;

import android.content.Context;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.json.*;

/** Shared implementation of the observed genuine Passport and Platform protocol. */
public class AccountClient {
    private static final String HOST="https://matrix-us.picovr.com";
    private static final String COMMON="multi_login=1&account_sdk_source=app&passport-sdk-version=30490&aid=308733&device_platform=android";
    public static final class Failure extends Exception {
        public final int code;
        public Failure(int code,String message) { super(message);this.code=code; }
    }
    private final Context context;
    private final TargetIdentity target;
    private final SessionStore store;
    private static final Object accountWork=new Object();
    public AccountClient(Context context,TargetIdentity target) {
        Context app=context.getApplicationContext();this.context=app==null?context:app;
        this.target=target;store=SessionStore.get(this.context);
    }
    public final TargetIdentity identity() {
        if(target==null) throw new IllegalStateException("Target identity required");return target;
    }
    static String hex(byte[] input) {
        StringBuilder out=new StringBuilder(input.length*2);
        for(byte b:input) out.append(String.format(Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private static String mixed(String input) { byte[] bytes=input.getBytes(StandardCharsets.UTF_8);for(int i=0;i<bytes.length;i++) bytes[i]^=5;return hex(bytes); }
    private static String form(Map<String,String> values) throws Exception {
        List<String> parts=new ArrayList<>();for(var entry:values.entrySet()) parts.add(URLEncoder.encode(entry.getKey(),"UTF-8")+"="+URLEncoder.encode(entry.getValue(),"UTF-8"));return String.join("&",parts);
    }
    private static String bounded(String input,int max) throws IOException {
        if(input.length()>max || input.contains("\r") || input.contains("\n")) throw new IOException("Invalid account field");return input;
    }
    private JSONObject request(String url,byte[] body,String contentType,JSONObject session,Map<String,String> extra) throws Exception {
        HttpURLConnection c=(HttpURLConnection)new URL(url).openConnection();
        try {
            c.setInstanceFollowRedirects(false);c.setConnectTimeout(6000);c.setReadTimeout(8000);
            c.setRequestProperty("User-Agent","pico_pui");
            if(url.startsWith(HOST+"/") && session!=null) {
                String token=bounded(session.optString("x_tt_token"),16384);if(!token.isEmpty()) c.setRequestProperty("X-Tt-Token",token);
                JSONObject cookies=session.optJSONObject("cookies");List<String> parts=new ArrayList<>();
                if(cookies!=null) for(Iterator<String> it=cookies.keys();it.hasNext();) { String name=it.next();parts.add(bounded(name,128)+"="+bounded(cookies.getString(name),16384)); }
                if(!parts.isEmpty()) c.setRequestProperty("Cookie",String.join("; ",parts));
            }
            for(var e:extra.entrySet()) c.setRequestProperty(e.getKey(),bounded(e.getValue(),16384));
            if(body!=null) {
                c.setRequestMethod("POST");c.setRequestProperty("Content-Type",contentType);c.setDoOutput(true);c.setFixedLengthStreamingMode(body.length);
                try(OutputStream out=c.getOutputStream()) { out.write(body); }
            }
            int status=c.getResponseCode();
            if(status!=200) throw new IOException("PICO HTTP "+status);
            JSONObject response;
            try(InputStream in=c.getInputStream()) { response=new JSONObject(new String(AccountIo.read(in,256*1024),StandardCharsets.UTF_8)); }
            if(url.startsWith(HOST+"/") && session!=null) {
                JSONObject cookies=session.optJSONObject("cookies");if(cookies==null) cookies=new JSONObject();
                int parsed=0,domainRejected=0,expired=0;Set<String> domains=new TreeSet<>();
                for(var entry:c.getHeaderFields().entrySet()) if("Set-Cookie".equalsIgnoreCase(entry.getKey())) for(String line:entry.getValue()) for(HttpCookie cookie:HttpCookie.parse(line)) {
                    parsed++;
                    String domain=cookie.getDomain();
                    if(domain!=null) {domain=domain.toLowerCase(Locale.ROOT);domains.add(domain);if(domain.startsWith(".")) domain=domain.substring(1);}
                    if(domain!=null && !("matrix-us.picovr.com".equals(domain) || "matrix-us.picovr.com".endsWith("."+domain))) {domainRejected++;continue;}
                    if(cookie.hasExpired()) {expired++;cookies.remove(cookie.getName());}else cookies.put(cookie.getName(),cookie.getValue());
                }
                android.util.Log.i("MatrixBridge","account cookies parsed="+parsed+" domainRejected="+domainRejected+" expired="+expired+" accepted="+cookies.length()+" domains="+domains);
                session.put("cookies",cookies);
                String token=c.getHeaderField("x-tt-token");if(token!=null && !token.isEmpty()) session.put("x_tt_token",bounded(token,16384));
            }
            return response;
        } finally { c.disconnect(); }
    }
    private JSONObject passport(String path,Map<String,String> params,boolean post,JSONObject session) throws Exception {
        String encoded=form(params);
        JSONObject response=request(HOST+path+"?"+COMMON+(post?"":"&"+encoded),post?encoded.getBytes(StandardCharsets.UTF_8):null,
            "application/x-www-form-urlencoded",session,Map.of());
        if(!"success".equals(response.optString("message"))) {
            JSONObject data=response.optJSONObject("data");int code=data==null?-1:data.optInt("error_code",-1);
            throw new Failure(-10001,"PICO 请求未成功（"+code+"）");
        }
        return response.getJSONObject("data");
    }
    public void sendCode(String email) throws Exception {
        validateEmail(email);
        passport("/passport/email/send_code/",Map.of("email",mixed(email),"type",mixed("13"),"email_logic_type","0","mix_mode","1"),true,new JSONObject());
    }
    private static void validateEmail(String email) {
        if(email==null || email.length()>254 || !email.matches("[^\\s@]+@[^\\s@]+\\.[^\\s@]+")) throw new IllegalArgumentException("请输入邮箱地址");
    }
    public void login(String email,String code) throws Exception {
        validateEmail(email);if(code==null || !code.matches("[A-Za-z0-9]{4,12}")) throw new IllegalArgumentException("请输入邮件中的验证码");
        long requested=store.generation();
        synchronized(accountWork) {
            long epoch;synchronized(store) {store.check(requested);store.clear();epoch=store.generation();}
            JSONObject session=new JSONObject();
            JSONObject data=passport("/passport/app/email/code_login/",Map.of("email",mixed(email),"ect_type","13","code",mixed(code),"mix_mode","1","email_logic_type","0"),true,session);
            session.put("uid",data.optString("user_id_str",data.optString("user_id"))).put("email",email);
            store.save(epoch,AccountData.passport(session));
        }
    }
    public String status() throws Exception {JSONObject s=store.read();return s==null?"尚未登录":s.optString("email","已登录");}
    public void logout() throws Exception {store.clear();}
    public JSONObject passportSession() throws Exception {
        synchronized(store) {JSONObject session=store.read();return session==null?null:AccountData.passport(session);}
    }
    public void importPassportSession(JSONObject session) throws Exception {
        long requested=store.generation();
        JSONObject clean=AccountData.passport(session);
        synchronized(accountWork) {synchronized(store) {store.check(requested);store.clear();store.save(store.generation(),clean);}}
    }
    private SessionStore.Snapshot snapshot() throws Exception {
        SessionStore.Snapshot snapshot=store.snapshot();
        if(snapshot.state==null) throw new Failure(-10004,"请登录 PICO 账号");return snapshot;
    }
    private JSONObject freshGrant(TargetIdentity identity,JSONObject session) throws Exception {
        String signer=TargetIdentity.signerSha256(context,identity.packageName), signature=identity.passportSignature(context);
        JSONObject info=passport("/passport/open/auth_info/v2/",Map.of("client_key",identity.appId,"scope","user_info","access_token",""),false,session);
        if(!info.optBoolean("login")) throw new Failure(-10004,"登录已过期，请重新登录");
        JSONObject token=passport("/passport/open/auth/",Map.of("client_key",identity.appId,"scope","user_info","device_platform","android",
            "signature",signature,"app_identity",hex(MessageDigest.getInstance("MD5").digest(identity.packageName.getBytes(StandardCharsets.UTF_8))),
            "aid","308733","skip_confirm","false","response_type","access_token","source","native"),true,session);
        AccountData.validateToken(token);token.put("obtained_at",System.currentTimeMillis()/1000);
        JSONObject grant=AccountData.grant(identity,signature,signer,token,user(identity,token.getString("access_token")));
        if(!signer.equals(TargetIdentity.signerSha256(context,identity.packageName))) throw new SecurityException("Application changed during authorization");
        return grant;
    }
    /** Always obtain a new grant. Host storage never owns the target's rotating tokens. */
    public JSONObject grantFor(String appId,String installedPackage) throws Exception {
        long requested=store.generation();
        synchronized(accountWork) {
            store.check(requested);
            TargetIdentity installed=TargetIdentity.installed(context,appId,installedPackage);
            SessionStore.Snapshot snapshot=snapshot();JSONObject passport=AccountData.passport(snapshot.state);
            JSONObject grant=freshGrant(installed,passport);
            store.save(snapshot.generation,AccountData.passport(passport));
            return grant;
        }
    }
    public void authorize() throws Exception {
        long requested=store.generation();
        synchronized(accountWork) {
            store.check(requested);
            TargetIdentity identity=identity();SessionStore.Snapshot snapshot=snapshot();
            JSONObject passport=AccountData.passport(snapshot.state), grant=freshGrant(identity,passport);
            JSONObject state=AccountData.targetState(grant);
            // Retain the local login only for the explicit research companion. An
            // embedded target needs its own refresh token, never Passport cookies.
            if(!identity.packageName.equals(context.getPackageName())) {
                for(Iterator<String> keys=passport.keys();keys.hasNext();) {String key=keys.next();state.put(key,passport.get(key));}
            }
            store.save(snapshot.generation,state);
        }
    }
    public JSONObject access() throws Exception {
        synchronized(accountWork) {
            TargetIdentity identity=identity();SessionStore.Snapshot snapshot=snapshot();JSONObject session=snapshot.state;
            JSONObject token=session.optJSONObject("platform");
            if(token==null) throw new Failure(-10005,"请登录 PICO 账号");
            if(!identity.passportSignature(context).equals(session.optString("clientSignature")) ||
                !identity.packageName.equals(session.optString("clientPackage")) || !identity.appId.equals(session.optString("appId")) ||
                (session.has("signerSha256") && !TargetIdentity.signerSha256(context,identity.packageName).equals(session.getString("signerSha256"))))
                throw new Failure(-10005,"应用授权不匹配，请重新连接");
            try {
                AccountData.validateToken(token);
                if(token.optLong("obtained_at")<=0 || token.optLong("obtained_at")>System.currentTimeMillis()/1000+60)
                    throw new IOException("Platform authorization timestamp invalid");
            } catch(IOException e) {throw new Failure(-10005,"应用授权不完整，请重新连接");}
            if(token.getLong("obtained_at")+token.getLong("expires_in")<=System.currentTimeMillis()/1000+60) {
                String refresh=token.optString("refresh_token");
                if(refresh.isEmpty()) throw new Failure(-10005,"请重新连接应用");
                JSONObject refreshed=passport("/passport/open/refresh_token/",Map.of("client_key",identity.appId,"grant_type","refresh_token","refresh_token",refresh),true,session);
                if(refreshed.optString("open_id").isEmpty()) refreshed.put("open_id",token.getString("open_id"));
                if(refreshed.optString("refresh_token").isEmpty()) refreshed.put("refresh_token",refresh);
                AccountData.validateToken(refreshed);refreshed.put("obtained_at",System.currentTimeMillis()/1000);
                JSONObject updated=AccountData.grant(identity,identity.passportSignature(context),TargetIdentity.signerSha256(context,identity.packageName),refreshed,user(identity,refreshed.getString("access_token")));
                if(identity.packageName.equals(context.getPackageName())) session=AccountData.targetState(updated);
                else session.put("platform",updated.getJSONObject("platform")).put("user",updated.getJSONObject("user"));
                store.save(snapshot.generation,session);
            }
            store.check(snapshot.generation);return session;
        }
    }
    public void importGrant(JSONObject grant) throws Exception {
        long requested=store.generation();
        TargetIdentity identity=identity();
        JSONObject clean=AccountData.importGrant(identity,context.getPackageName(),identity.passportSignature(context),
            TargetIdentity.signerSha256(context,identity.packageName),grant,System.currentTimeMillis()/1000);
        synchronized(accountWork) {synchronized(store) {store.check(requested);store.clear();store.save(store.generation(),clean);}}
    }
    public boolean hasGrant() throws Exception {
        try {JSONObject user=access().optJSONObject("user");return user!=null && !user.optString("account_id").isEmpty();}
        catch(Failure e) {if(e.code==-10004 || e.code==-10005) return false;throw e;}
    }
    private static String hmac(String key,byte[] data) throws Exception {
        Mac mac=Mac.getInstance("HmacSHA256");mac.init(new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8),"HmacSHA256"));return hex(mac.doFinal(data));
    }
    private JSONObject user(TargetIdentity identity,String token) throws Exception {
        byte[] body="{}".getBytes(StandardCharsets.UTF_8);String prefix="auth-v2/"+identity.appId+"/"+(System.currentTimeMillis()/1000)+"/1800";
        String auth=prefix+"/"+hmac(hmac(identity.agwKey,prefix.getBytes(StandardCharsets.UTF_8)),body);
        JSONObject response=request("https://platform-us.picovr.com/account/v1/info/current",body,"application/json",null,Map.of("Agw-Auth",auth,"X-Access-Token",token));
        if(response.optInt("code",-1)!=0) throw new Failure(-10001,"暂时无法获取 PICO 用户资料");
        JSONObject user=response.getJSONObject("data").getJSONObject("user");
        if(user.optString("account_id").isEmpty()) throw new IOException("Platform user incomplete");return user;
    }
}
