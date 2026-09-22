package org.picomatrix.bridge.adapter;

import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.json.*;

/** Bounded binary XML reader; resource IDs are retained, never guessed. */
public final class BinaryManifest {
    private final ByteBuffer data;
    private final List<String> strings = new ArrayList<>();
    public BinaryManifest(byte[] bytes) {
        if (bytes.length < 8 || bytes.length > 8 * 1024 * 1024) throw new IllegalArgumentException("invalid manifest size");
        data = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
    }
    private int u16(int p) { return Short.toUnsignedInt(data.getShort(p)); }
    private int i32(int p) { return data.getInt(p); }
    private String text(int index) {
        if (index == -1) return "";
        if (index < 0 || index >= strings.size()) throw new IllegalArgumentException("invalid string index");
        return strings.get(index);
    }
    private int[] length8(int p) {
        int n = Byte.toUnsignedInt(data.get(p++));
        if ((n & 128) != 0) n = ((n & 127) << 8) | Byte.toUnsignedInt(data.get(p++));
        return new int[]{n, p};
    }
    private int[] length16(int p) {
        int n = u16(p); p += 2;
        if ((n & 32768) != 0) { n = ((n & 32767) << 16) | u16(p); p += 2; }
        return new int[]{n, p};
    }
    public JSONObject read() {
        if (u16(0) != 3 || u16(2)!=8 || i32(4) != data.capacity()) throw new IllegalArgumentException("not complete Android binary XML");
        JSONObject root = new JSONObject(); JSONArray components = new JSONArray(), permissions = new JSONArray(), metadata = new JSONArray();
        int pos = u16(2);
        while (pos < data.capacity()) {
            if (pos > data.capacity() - 8) throw new IllegalArgumentException("truncated XML chunk");
            int type = u16(pos), header = u16(pos+2), size = i32(pos+4);
            if (size < header || header < 8 || size > data.capacity()-pos) throw new IllegalArgumentException("invalid XML chunk");
            if (type == 1) {
                if (header < 28 || !strings.isEmpty()) throw new IllegalArgumentException("invalid string pool");
                int count = i32(pos+8), flags = i32(pos+16), start = i32(pos+20);
                if (count < 0 || count > (size-header)/4 || start < header || start >= size) throw new IllegalArgumentException("invalid pool bounds");
                for (int i=0; i<count; i++) {
                    int offset = i32(pos+header+i*4);
                    if (offset < 0 || offset >= size-start) throw new IllegalArgumentException("invalid pool offset");
                    int at = pos+start+offset; int[] len;
                    boolean utf8 = (flags & 256) != 0;
                    if (utf8) { len = length8(at); len = length8(len[1]); }
                    else len = length16(at);
                    long byteCount = (long)len[0] * (utf8 ? 1 : 2);
                    if (byteCount < 0 || byteCount > pos+size-len[1]) throw new IllegalArgumentException("truncated string");
                    byte[] bytes = new byte[(int)byteCount];
                    ByteBuffer copy = data.duplicate(); ((Buffer)copy).position(len[1]); copy.get(bytes);
                    strings.add(new String(bytes, utf8 ? StandardCharsets.UTF_8 : StandardCharsets.UTF_16LE));
                }
            } else if (type == 0x102) {
                if (size < 36) throw new IllegalArgumentException("truncated element");
                String tag = text(i32(pos+20));
                int first=pos+16+u16(pos+24), width=u16(pos+26), count=u16(pos+28);
                if (width < 20 || first < pos+36 || (long)first+(long)width*count>pos+size) throw new IllegalArgumentException("invalid attributes");
                JSONObject attrs = new JSONObject();
                for (int i=0; i<count; i++) {
                    int at=first+i*width, kind=Byte.toUnsignedInt(data.get(at+15)), value=i32(at+16);
                    String name=text(i32(at+4));
                    Object decoded = switch(kind) {
                        case 3 -> text(value);
                        case 0x12 -> value != 0;
                        case 0x10, 0x11 -> value;
                        default -> "@0x"+Integer.toHexString(value);
                    };
                    attrs.put(name, decoded);
                }
                if (tag.equals("manifest")) root = attrs;
                else if (Portable.set("application", "activity", "activity-alias", "service", "receiver", "provider").contains(tag)) components.put(attrs.put("kind", tag));
                else if (tag.equals("uses-permission") || tag.equals("permission")) permissions.put(attrs.put("kind", tag));
                else if (tag.equals("meta-data")) metadata.put(attrs);
            }
            pos += size;
        }
        if(!root.has("package") || !(root.get("package") instanceof String)) throw new IllegalArgumentException("missing manifest package");
        return root.put("components", components).put("permissions", permissions).put("metadata",metadata);
    }
}
