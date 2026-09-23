package org.picomatrix.bridge.adapter;

import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import org.json.*;
import net.jpountz.lz4.*;

/** Applies only preselected integrity constants. Never changes comparison or branch opcodes. */
public final class IntegrityRecipe {
    private static int i32(byte[] b,int p) { bounds(b,p,4);return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt(p); }
    private static void put32(byte[] b,int p,int n) { bounds(b,p,4);ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putInt(p,n); }
    private static void put64(byte[] b,int p,long n) { bounds(b,p,8);ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).putLong(p,n); }
    private static void bounds(byte[] b,int p,int n) { Portable.require(p>=0&&n>=0&&p<=b.length-n,"Recipe offset out of bounds"); }
    static int signerHash(byte[] certificate,String kind) throws Exception {
        if(kind.equals("java")) return Arrays.hashCode(certificate);
        Portable.require(kind.equals("x509"),"Unknown signer hash");
        return ByteBuffer.wrap(MessageDigest.getInstance("SHA-1").digest(certificate)).getInt();
    }
    static byte[] userString(String text) {
        byte[] content=text.getBytes(StandardCharsets.UTF_16LE);int size=content.length+1;
        int prefix=size<0x80?1:size<0x4000?2:4;byte[] result=new byte[prefix+size];
        if(prefix==1)result[0]=(byte)size;
        else if(prefix==2){result[0]=(byte)((size>>>8)|0x80);result[1]=(byte)size;}
        else{result[0]=(byte)((size>>>24)|0xc0);result[1]=(byte)(size>>>16);result[2]=(byte)(size>>>8);result[3]=(byte)size;}
        System.arraycopy(content,0,result,prefix,content.length);return result;
    }
    public static byte[] assembly(byte[] original,JSONObject rule,byte[] certificate,byte[] routedLoader) throws Exception {
        Portable.require(Portable.sha(original).equals(rule.getString("sha256")),"Managed assembly hash changed");
        byte[] result=original.clone();BitSet touched=new BitSet(original.length);JSONArray patches=rule.getJSONArray("patches");
        for(int n=0;n<patches.length();n++) {
            JSONObject patch=patches.getJSONObject(n);int at=patch.getInt("offset");byte[] expected=Portable.unhex(patch.getString("expectedHex"));
            bounds(original,at,expected.length);Portable.require(Arrays.equals(expected,Arrays.copyOfRange(original,at,at+expected.length)),"Expected integrity operand differs");
            Portable.require(touched.nextSetBit(at)<0||touched.nextSetBit(at)>=at+expected.length,"Overlapping integrity operands");touched.set(at,at+expected.length);
            String kind=patch.getString("kind");byte[] replacement;
            if(kind.equals("certificate"))replacement=userString(Portable.hex(certificate));
            else if(kind.equals("loaderMd5"))replacement=userString(Base64.getEncoder().encodeToString(MessageDigest.getInstance("MD5").digest(routedLoader)));
            else {
                Portable.require(kind.equals("hash32")&&expected.length==4,"Unknown integrity operand");
                int opcode=patch.getInt("opcodeOffset");bounds(original,opcode,1);
                Portable.require((original[opcode]&255)==patch.getInt("opcode"),"Signer comparison opcode changed");
                replacement=ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(signerHash(certificate,patch.getString("hash"))-patch.getInt("subtract")).array();
            }
            Portable.require(replacement.length<=expected.length,"Actual signer certificate exceeds checked metadata slot");
            if(kind.equals("loaderMd5"))Portable.require(replacement.length==expected.length,"Loader hash length changed");
            Arrays.fill(result,at,at+expected.length,(byte)0);System.arraycopy(replacement,0,result,at,replacement.length);
        }
        return result;
    }
    public static byte[] aot(byte[] original,JSONObject rule,byte[] certificate) throws Exception {
        Portable.require(Portable.sha(original).equals(rule.getString("sha256")),"AOT hash changed");
        byte[] result=original.clone();Set<Integer> touched=new HashSet<>();JSONArray comparisons=rule.getJSONArray("comparisons");
        Portable.require(comparisons.length()==3,"Expected three signer comparisons");
        for(int i=0;i<comparisons.length();i++) {
            JSONObject c=comparisons.getJSONObject(i);int expected=c.getInt("expected"),replacement=signerHash(certificate,c.getString("hash"));
            Portable.require(i32(original,c.getInt("compare"))==0x6b08001f,"AOT comparison opcode changed");
            for(int shift:new int[]{0,16}) {
                int at=c.getInt(shift==0?"low":"high"),opcode=shift==0?0x52800008:0x72a00008;
                Portable.require(at%4==0&&touched.add(at),"Overlapping native operands");
                Portable.require(i32(original,at)==(opcode|(((expected>>>shift)&65535)<<5)),"AOT signer operand changed");
                put32(result,at,opcode|(((replacement>>>shift)&65535)<<5));
            }
        }
        return result;
    }
    public static byte[] store(byte[] original,JSONObject rule,byte[] certificate,byte[] routedLoader) throws Exception {
        Portable.require(Portable.sha(original).equals(rule.getString("sha256")),"Managed store hash changed");
        int base=rule.getInt("payloadOffset"),size=rule.getInt("payloadSize"),table=rule.getInt("sectionTableOffset");
        bounds(original,base,size);Portable.require(table>=base+size&&i32(original,0)==0x464c457f,"Unsupported ELF store");
        byte[] result=original.clone();java.io.ByteArrayOutputStream extension=new java.io.ByteArrayOutputStream();
        JSONArray assemblies=rule.getJSONArray("assemblies");Set<Integer> descriptors=new HashSet<>();
        Portable.require(assemblies.length()==3,"Expected three managed assemblies");
        LZ4Factory lz4=LZ4Factory.safeInstance();
        for(int i=0;i<assemblies.length();i++) {
            JSONObject a=assemblies.getJSONObject(i);int desc=base+a.getInt("descriptorOffset"),start=a.getInt("start"),length=a.getInt("compressedSize"),uncompressed=a.getInt("uncompressedSize");
            Portable.require(descriptors.add(desc)&&start>=0&&length>=12&&start<=size-length,"Invalid assembly extent");
            Portable.require(i32(original,desc+4)==start&&i32(original,desc+8)==length,"Store descriptor changed");
            Portable.require(i32(original,base+start)==0x5a4c4158&&i32(original,base+start+8)==uncompressed&&uncompressed>0&&uncompressed<16*1024*1024,"Compression header changed");
            byte[] assembly=lz4.safeDecompressor().decompress(original,base+start+12,length-12,uncompressed);
            Portable.require(assembly.length==uncompressed,"Wrong decompressed size");
            byte[] patched=assembly(assembly,a,certificate,routedLoader),compressed=lz4.highCompressor(12).compress(patched);
            Portable.require(Arrays.equals(patched,lz4.safeDecompressor().decompress(compressed,patched.length)),"LZ4 round trip failed");
            byte[] data=new byte[12+compressed.length];System.arraycopy(original,base+start,data,0,12);System.arraycopy(compressed,0,data,12,compressed.length);
            int updated=start;
            if(data.length<=length) {Arrays.fill(result,base+start,base+start+length,(byte)0);System.arraycopy(data,0,result,base+start,data.length);}
            else {updated=size+extension.size();extension.write(data);int padding=(-data.length)&7;extension.write(new byte[padding]);}
            put32(result,desc+4,updated);put32(result,desc+8,data.length);
        }
        byte[] added=extension.toByteArray();
        if(added.length!=0) {
            Portable.require(added.length<16*1024*1024,"Unexpected store growth");int end=base+size;byte[] expanded=new byte[result.length+added.length];
            System.arraycopy(result,0,expanded,0,end);System.arraycopy(added,0,expanded,end,added.length);System.arraycopy(result,end,expanded,end+added.length,result.length-end);result=expanded;
            put64(result,40,(long)table+added.length);put64(result,table+added.length+rule.getInt("payloadSectionIndex")*64+32,(long)size+added.length);
        }
        return result;
    }
}
