package org.picomatrix.bridge.adapter;

import java.nio.file.Path;
import java.util.Map;
import org.json.JSONObject;

/** Stable API implemented by a separately signed application profile. */
public interface ApplicationProfile {
    int API_VERSION = 1;

    /** Immutable identity and account metadata used for routing and UI badges. */
    JSONObject metadata();

    /** Verify targeted inputs and return complete replacement APK entries. */
    Map<String,byte[]> prepare(Path original, JSONObject inspection, byte[] targetCertificateDer,
        String outputPackage) throws Exception;

    /** Application-specific postconditions after the generic unsigned APK writer. */
    void verify(Path original, Path unsigned, Map<String,byte[]> replacements) throws Exception;
}
