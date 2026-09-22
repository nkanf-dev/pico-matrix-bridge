package org.picomatrix.bridge.protocol;
import static org.junit.Assert.*;
import org.junit.Test;

public class WireTest {
    @Test public void decodesIndependentWireFixture() {
        Wire response=Wire.parse(new byte[]{8,(byte)0x84,(byte)0x9d,1,16,0,50,3,97,98,99,58,0});
        assertEquals(20100,response.number(1,-1));assertEquals(0,response.number(2,-1));
        assertEquals("abc",response.string(6));assertEquals(0,response.bytes(7).length);
    }
    @Test public void negativeStatusUsesTenByteInt64Encoding() {
        byte[] bytes=new Wire.Builder().number(2,-3).build();
        assertArrayEquals(new byte[]{16,(byte)0xfd,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,1},bytes);
        assertEquals(-3,Wire.parse(bytes).number(2,0));
    }
    @Test public void rejectsMalformedAndAmbiguousFields() {
        for(byte[] invalid:new byte[][]{{0},{8,(byte)128},{10,5,1},{13,1},{11},{8,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,2}})
            assertThrows(IllegalArgumentException.class,()->Wire.parse(invalid));
        assertThrows(IllegalArgumentException.class,()->Wire.parse(new byte[]{10,1,97,10,1,98}).string(1));
        assertThrows(IllegalArgumentException.class,()->Wire.parse(new byte[]{10,1,(byte)255}).string(1));
        assertThrows(IllegalArgumentException.class,()->Wire.parse(new byte[Wire.MAX_BYTES+1]));
    }
    @Test public void skipsUnknownFixedFieldsAndPreservesRepeatedStrings() {
        Wire message=Wire.parse(new byte[]{13,0,0,0,0,18,1,97,18,1,98});
        assertEquals(java.util.List.of("a","b"),message.strings(2));
    }
}
