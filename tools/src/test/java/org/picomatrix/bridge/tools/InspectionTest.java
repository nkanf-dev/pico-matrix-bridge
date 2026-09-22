package org.picomatrix.bridge.tools;
import org.picomatrix.bridge.adapter.*;
import static org.junit.Assert.*;
import org.junit.Test;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.jf.dexlib2.immutable.*;
import org.jf.dexlib2.immutable.value.*;

public class InspectionTest {
    private static final String TYPE="Lcom/bytedance/pico/matrix/proto/Example;";
    private static ImmutableField field(String name,int tag) {
        return new ImmutableField(TYPE,name,"Ljava/lang/String;",1,null,List.of(new ImmutableAnnotation(1,"Lcom/squareup/wire/WireField;",List.of(
            new ImmutableAnnotationElement("tag",new ImmutableIntEncodedValue(tag)),
            new ImmutableAnnotationElement("adapter",new ImmutableStringEncodedValue("com.squareup.wire.ProtoAdapter#STRING"))
        ))),Set.of());
    }
    private static ImmutableClassDef definition(ImmutableField... fields) {
        return new ImmutableClassDef(TYPE,1,"Lcom/squareup/wire/Message;",List.of(),null,List.of(),List.of(fields),List.of());
    }
    @Test public void extractsAnnotationsWithoutDecompiler() {
        Contracts contracts=new Contracts();contracts.accept(definition(field("email",7)));
        var field=contracts.json().getJSONObject("messages").getJSONArray(TYPE).getJSONObject(0);
        assertEquals(7,field.getInt("tag"));assertEquals("email",field.getString("name"));
        assertEquals("com.squareup.wire.ProtoAdapter#STRING",field.getString("adapter"));
    }
    @Test public void rejectsAmbiguousContracts() {
        assertThrows(IllegalArgumentException.class,()->new Contracts().accept(definition(field("a",1),field("b",1))));
        Contracts contracts=new Contracts();contracts.accept(definition(field("a",1)));
        assertThrows(IllegalArgumentException.class,()->contracts.accept(definition(field("b",2))));
    }
    @Test public void nativeDetectionSpansReadBoundary() throws Exception {
        byte[] needle=Main.MATRIX.getBytes(StandardCharsets.US_ASCII),bytes=new byte[65536+40];
        System.arraycopy(needle,0,bytes,65530,needle.length);
        assertTrue(Main.nativeReferences(new ByteArrayInputStream(bytes)));
        assertFalse(Main.nativeReferences(new ByteArrayInputStream(new byte[70000])));
    }
    @Test public void rejectsIncompleteManifestAndOversizedEntry() {
        assertThrows(IllegalArgumentException.class,()->new BinaryManifest(new byte[]{3,0,8,0,8,0,0,0}).read());
        assertThrows(IllegalArgumentException.class,()->new BinaryManifest(new byte[]{3,0,0,0,8,0,0,0}).read());
        assertThrows(IOException.class,()->Main.bounded(new ByteArrayInputStream(new byte[33]),32));
    }
    @Test public void rejectsDriverOnlyBootstrapBeforeNativeClassLookupFails() throws Exception {
        Set<String> types=new HashSet<>(EmbeddedDex.REQUIRED_BOOTSTRAP);
        types.remove("Lcom/bytedance/pico/matrix/server/ServerBrokerJni;");
        IOException failure=assertThrows(IOException.class,()->EmbeddedDex.requireBootstrap(types));
        assertTrue(failure.getMessage().contains("ServerBrokerJni"));
        types.add("Lcom/bytedance/pico/matrix/server/ServerBrokerJni;");
        EmbeddedDex.requireBootstrap(types);
    }
}
