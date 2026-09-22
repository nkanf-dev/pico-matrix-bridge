package org.picomatrix.bridge.adapter;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import org.json.*;

/** APIs shared by Android 29 and desktop Java; no desktop process or JNI calls. */
final class Portable {
    static void require(boolean ok,String message) { if(!ok) throw new IllegalArgumentException(message); }
    static String hex(byte[] bytes) { char[] chars=new char[bytes.length*2];String digits="0123456789abcdef";for(int i=0;i<bytes.length;i++){chars[i*2]=digits.charAt((bytes[i]&255)>>>4);chars[i*2+1]=digits.charAt(bytes[i]&15);}return new String(chars); }
    static byte[] unhex(String value) { require(value.length()%2==0,"Invalid hex length");byte[] result=new byte[value.length()/2];for(int i=0;i<result.length;i++){int a=Character.digit(value.charAt(i*2),16),b=Character.digit(value.charAt(i*2+1),16);require(a>=0&&b>=0,"Invalid hex");result[i]=(byte)(a*16+b);}return result; }
    static String sha(byte[] bytes) throws Exception { return hex(MessageDigest.getInstance("SHA-256").digest(bytes)); }
    static String sha(Path path) throws Exception { MessageDigest d=MessageDigest.getInstance("SHA-256");try(InputStream in=Files.newInputStream(path)){byte[] b=new byte[65536];int n;while((n=in.read(b))!=-1)d.update(b,0,n);}return hex(d.digest()); }
    static byte[] read(InputStream in,int max) throws IOException { ByteArrayOutputStream out=new ByteArrayOutputStream();byte[] b=new byte[Math.min(max+1,65536)];int n;while((n=in.read(b))!=-1){if(n>max-out.size())throw new IOException("Entry exceeds size limit");out.write(b,0,n);}return out.toByteArray(); }
    static JSONObject json(Path file) throws Exception { try(InputStream in=Files.newInputStream(file)){return new JSONObject(new String(read(in,4*1024*1024),StandardCharsets.UTF_8));} }
    static void json(Path file,JSONObject value) throws Exception { Files.write(file,(value.toString(2)+"\n").getBytes(StandardCharsets.UTF_8)); }
    @SafeVarargs static <T> Set<T> set(T... values) { return new HashSet<>(Arrays.asList(values)); }
    static Set<String> keys(JSONObject object) { Set<String> result=new HashSet<>();Iterator<String> it=object.keys();while(it.hasNext())result.add(it.next());return result; }
    static void deleteTree(Path directory) throws IOException { if(!Files.exists(directory))return;try(java.util.stream.Stream<Path> paths=Files.walk(directory)){Iterator<Path> it=paths.sorted(Comparator.reverseOrder()).iterator();while(it.hasNext())Files.delete(it.next());} }
}
