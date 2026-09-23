package org.picomatrix.bridge.adapter;

import java.util.*;
import org.json.*;
import org.jf.dexlib2.iface.*;
import org.jf.dexlib2.iface.value.*;
import org.jf.dexlib2.iface.instruction.*;
import org.jf.dexlib2.iface.reference.*;

/** Extracts declarations, not reconstructed Java or inferred runtime behavior. */
public final class Contracts {
    private final SortedMap<String, Object> commands = new TreeMap<>();
    private final SortedMap<String, Object> messages = new TreeMap<>();
    private void command(String name,int value) {
        Object old=commands.putIfAbsent(name,value);
        if(old!=null && !old.equals(value)) throw new IllegalArgumentException("conflicting command: "+name);
    }
    public void accept(ClassDef cls) {
        String type = cls.getType();
        if (!type.startsWith("Lcom/bytedance/pico/matrix/proto/")) return;
        if (type.endsWith("/MATRIX_CMD_CONSTKt;")) {
            for (Field field : cls.getStaticFields()) {
                if (field.getName().startsWith("CMD_") && field.getInitialValue() instanceof IntEncodedValue value) {
                    command(field.getName(),value.getValue());
                }
            }
        }
        if (type.endsWith("/MATRIX_CMD;")) {
            for(Method method:cls.getDirectMethods()) {
                if(!method.getName().equals("<clinit>") || method.getImplementation()==null) continue;
                Map<Integer,Object> registers=new HashMap<>(); Set<String> found=new HashSet<>();
                for(Instruction instruction:method.getImplementation().getInstructions()) {
                    String opcode=instruction.getOpcode().name();
                    if(instruction instanceof ReferenceInstruction ri && ri.getReference() instanceof StringReference s && instruction instanceof OneRegisterInstruction one) registers.put(one.getRegisterA(),s.getString());
                    else if(opcode.startsWith("CONST") && instruction instanceof NarrowLiteralInstruction literal && instruction instanceof OneRegisterInstruction one) registers.put(one.getRegisterA(),literal.getNarrowLiteral());
                    else if(opcode.startsWith("MOVE") && instruction instanceof TwoRegisterInstruction move) {
                        Object value=registers.get(move.getRegisterB()); if(value==null) registers.remove(move.getRegisterA()); else registers.put(move.getRegisterA(),value);
                    } else if(instruction instanceof ReferenceInstruction ri && ri.getReference() instanceof MethodReference mr && mr.getDefiningClass().equals(type) && mr.getName().equals("<init>") && instruction instanceof FiveRegisterInstruction call && call.getRegisterCount()==4) {
                        Object name=registers.get(call.getRegisterD()), value=registers.get(call.getRegisterF());
                        if(!(name instanceof String n) || !(value instanceof Integer v)) throw new IllegalArgumentException("unresolved command initializer");
                        command(n,v); found.add(n);
                    } else if(instruction instanceof OneRegisterInstruction one && !opcode.startsWith("SPUT")) registers.remove(one.getRegisterA());
                }
                for(Field field:cls.getStaticFields()) if(field.getType().equals(type) && !found.contains(field.getName())) throw new IllegalArgumentException("command extraction incomplete: "+field.getName());
            }
        }
        List<Map<String, Object>> fields = new ArrayList<>();
        Set<Integer> tags = new HashSet<>();
        for (Field field : cls.getFields()) {
            for (Annotation annotation : field.getAnnotations()) {
                if (!annotation.getType().equals("Lcom/squareup/wire/WireField;")) continue;
                Map<String, Object> data = new TreeMap<>();
                data.put("name", field.getName()); data.put("type", field.getType());
                for (AnnotationElement element : annotation.getElements()) {
                    data.put(element.getName(), value(element.getValue()));
                }
                if (!(data.get("tag") instanceof Integer tag) || tag <= 0 || !tags.add(tag))
                    throw new IllegalArgumentException("invalid/duplicate protobuf tag: " + type);
                if (!(data.get("adapter") instanceof String))
                    throw new IllegalArgumentException("missing adapter: " + type + "." + field.getName());
                fields.add(data);
            }
        }
        if (!fields.isEmpty()) {
            fields.sort(Comparator.comparingInt(f -> (Integer)f.get("tag")));
            if (messages.putIfAbsent(type, fields) != null)
                throw new IllegalArgumentException("duplicate message: " + type);
        }
    }
    private Object value(EncodedValue value) {
        if (value instanceof StringEncodedValue v) return v.getValue();
        if (value instanceof IntEncodedValue v) return v.getValue();
        if (value instanceof BooleanEncodedValue v) return v.getValue();
        if (value instanceof EnumEncodedValue v) return v.getValue().getName();
        throw new IllegalArgumentException("unsupported WireField metadata type " + value.getValueType());
    }
    public JSONObject json() {
        return new JSONObject().put("commands", new JSONObject(commands)).put("messages", new JSONObject(messages))
            .put("commandCount", commands.size()).put("messageCount", messages.size());
    }
}
