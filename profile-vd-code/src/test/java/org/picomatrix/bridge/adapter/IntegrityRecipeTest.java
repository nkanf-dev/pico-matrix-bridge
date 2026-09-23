package org.picomatrix.bridge.adapter;

import org.junit.Test;
import static org.junit.Assert.*;
import org.json.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class IntegrityRecipeTest {
    @Test public void actualSignerUpdatesOnlyCheckedOperands() throws Exception {
        byte[] cert={1,2,(byte)200},image=new byte[80];Arrays.fill(image,(byte)0x4a);image[9]=0x20;
        ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN).putInt(10,4567);
        JSONObject patch=new JSONObject().put("offset",10).put("expectedHex",Portable.hex(Arrays.copyOfRange(image,10,14)))
            .put("kind","hash32").put("hash","java").put("subtract",22).put("opcodeOffset",9).put("opcode",0x20);
        JSONObject rule=new JSONObject().put("sha256",Portable.sha(image)).put("patches",new JSONArray().put(patch));
        byte[] result=IntegrityRecipe.assembly(image,rule,cert,new byte[0]);
        assertEquals(Arrays.hashCode(cert)-22,ByteBuffer.wrap(result).order(ByteOrder.LITTLE_ENDIAN).getInt(10));
        for(int i=0;i<image.length;i++)if(i<10||i>=14)assertEquals(image[i],result[i]);
        assertEquals(4567,ByteBuffer.wrap(image).order(ByteOrder.LITTLE_ENDIAN).getInt(10));
        patch.put("offset",11);assertThrows(IllegalArgumentException.class,()->IntegrityRecipe.assembly(image,rule,cert,new byte[0]));
    }
    @Test public void changedHashOpcodeAndOverlappingOperandsFailClosed() throws Exception {
        byte[] image={0x20,1,2,3,4};JSONObject patch=new JSONObject().put("offset",1).put("expectedHex","01020304").put("kind","hash32").put("hash","java").put("subtract",0).put("opcodeOffset",0).put("opcode",0x20);
        JSONObject rule=new JSONObject().put("sha256",Portable.sha(image)).put("patches",new JSONArray().put(patch).put(patch));
        assertThrows(IllegalArgumentException.class,()->IntegrityRecipe.assembly(image,rule,new byte[]{1},new byte[0]));
        rule.put("patches",new JSONArray().put(patch));patch.put("opcode",0x21);
        assertThrows(IllegalArgumentException.class,()->IntegrityRecipe.assembly(image,rule,new byte[]{1},new byte[0]));
        image[0]=0x21;assertThrows(IllegalArgumentException.class,()->IntegrityRecipe.assembly(image,rule,new byte[]{1},new byte[0]));
    }
    @Test public void replacementCertificateCannotRelocateMetadata() throws Exception {
        byte[] image=IntegrityRecipe.userString("ff");JSONObject rule=new JSONObject().put("sha256",Portable.sha(image)).put("patches",new JSONArray().put(new JSONObject().put("offset",0).put("expectedHex",Portable.hex(image)).put("kind","certificate")));
        assertThrows(IllegalArgumentException.class,()->IntegrityRecipe.assembly(image,rule,new byte[]{1,2},new byte[0]));
        byte[] result=IntegrityRecipe.assembly(image,rule,new byte[]{0x12},new byte[0]);assertArrayEquals(IntegrityRecipe.userString("12"),result);
    }
    @Test public void javaAndX509HashAlgorithmsRemainDistinct() throws Exception {
        byte[] cert="certificate".getBytes(StandardCharsets.UTF_8);
        assertEquals(Arrays.hashCode(cert),IntegrityRecipe.signerHash(cert,"java"));
        assertEquals(ByteBuffer.wrap(java.security.MessageDigest.getInstance("SHA-1").digest(cert)).getInt(),IntegrityRecipe.signerHash(cert,"x509"));
        assertThrows(IllegalArgumentException.class,()->IntegrityRecipe.signerHash(cert,"unknown"));
    }
}
