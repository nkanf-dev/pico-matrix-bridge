package org.picomatrix.bridge.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;

/** Small bounded protobuf envelope reader. No dependency on obfuscated vendor classes. */
public final class Wire {
    public static final int MAX_BYTES = 512 * 1024;
    private static final int MAX_FIELDS = 4096;
    private final Map<Integer,List<Object>> fields = new HashMap<>();
    private final byte[] data;
    private int position;
    private Wire(byte[] data) { this.data = data; }

    public static Wire parse(byte[] data) {
        if (data == null || data.length > MAX_BYTES) throw new IllegalArgumentException("invalid message size");
        Wire result = new Wire(data);
        int count = 0;
        while (result.position < data.length) {
            if (++count > MAX_FIELDS) throw new IllegalArgumentException("too many fields");
            long key = result.varint();
            if (key <= 0 || key >>> 3 > 0x1fffffff) throw new IllegalArgumentException("invalid protobuf tag");
            int tag = (int)(key >>> 3), kind = (int)(key & 7);
            if (tag == 0) throw new IllegalArgumentException("zero tag");
            Object value;
            switch (kind) {
                case 0: value = result.varint(); break;
                case 2:
                    long length = result.varint();
                    if (length < 0 || length > data.length-result.position) throw new IllegalArgumentException("truncated field");
                    value = Arrays.copyOfRange(data, result.position, result.position+(int)length);
                    result.position += (int)length;
                    break;
                case 1: result.skip(8); continue;
                case 5: result.skip(4); continue;
                default: throw new IllegalArgumentException("unsupported protobuf wire type");
            }
            result.fields.computeIfAbsent(tag, unused -> new ArrayList<>()).add(value);
        }
        return result;
    }
    private void skip(int size) {
        if (size > data.length-position) throw new IllegalArgumentException("truncated fixed field");
        position += size;
    }
    private long varint() {
        long value = 0;
        for (int i=0;i<10;i++) {
            if (position == data.length) throw new IllegalArgumentException("truncated varint");
            int b = data[position++] & 255;
            if (i == 9 && b > 1) throw new IllegalArgumentException("overflowed varint");
            value |= (long)(b & 127) << (i*7);
            if ((b & 128) == 0) return value;
        }
        throw new IllegalArgumentException("overflowed varint");
    }
    private Object one(int tag) {
        List<Object> values = fields.get(tag);
        if (values == null) return null;
        if (values.size() != 1) throw new IllegalArgumentException("duplicate singular field");
        return values.get(0);
    }
    public byte[] bytes(int tag) {
        Object value=one(tag);
        if (value == null) return new byte[0];
        if (!(value instanceof byte[] b)) throw new IllegalArgumentException("wrong field type");
        return b.clone();
    }
    public long number(int tag, long fallback) {
        Object value=one(tag);
        if (value == null) return fallback;
        if (!(value instanceof Long n)) throw new IllegalArgumentException("wrong field type");
        return n;
    }
    private static String string(byte[] bytes) {
        try { return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString(); }
        catch (CharacterCodingException e) { throw new IllegalArgumentException("invalid UTF-8"); }
    }
    public String string(int tag) { return string(bytes(tag)); }
    public List<String> strings(int tag) {
        List<String> result=new ArrayList<>();
        for (Object value:fields.getOrDefault(tag, Collections.emptyList())) {
            if (!(value instanceof byte[] b)) throw new IllegalArgumentException("wrong repeated field type");
            result.add(string(b));
        }
        return Collections.unmodifiableList(result);
    }
    public static final class Builder {
        private final ByteArrayOutputStream out=new ByteArrayOutputStream();
        private void varint(long value) {
            do { int b=(int)value&127; value>>>=7; out.write(value==0?b:b|128); } while(value!=0);
        }
        private void key(int tag,int kind) {
            if(tag<=0 || tag>0x1fffffff) throw new IllegalArgumentException("invalid tag");
            varint(((long)tag<<3)|kind);
        }
        private void check() { if(out.size()>MAX_BYTES) throw new IllegalArgumentException("message too large"); }
        public Builder number(int tag,long value) { key(tag,0);varint(value);check();return this; }
        public Builder bytes(int tag,byte[] value) {
            if (value.length>MAX_BYTES || value.length>MAX_BYTES-out.size()-10) throw new IllegalArgumentException("message too large");
            key(tag,2);varint(value.length);out.write(value,0,value.length);check();return this;
        }
        public Builder string(int tag,String value) { return bytes(tag,value.getBytes(StandardCharsets.UTF_8)); }
        public byte[] build() { return out.toByteArray(); }
    }
}
