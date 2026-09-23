package org.picomatrix.bridge.tools;

import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Path;
import org.json.JSONObject;
import org.junit.Test;
import org.picomatrix.bridge.adapter.ApplicationProfile;
import org.picomatrix.bridge.adapter.VdProfile;
import org.picomatrix.bridge.adapter.GenericMatrixProfile;
import static org.junit.Assert.*;

/** Profile APKs use a child loader, so a shared package name grants no package-private access. */
public class ProfileClassLoaderTest {
    @Test public void independentlyLoadedProfilesCanCallHostApi() throws Exception {
        for (Class<?> type : new Class<?>[]{VdProfile.class, GenericMatrixProfile.class}) {
            try (URLClassLoader loader = new URLClassLoader(new URL[]{type.getProtectionDomain().getCodeSource().getLocation()}, type.getClassLoader()) {
                @Override protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                    if (!name.equals(type.getName())) return super.loadClass(name, resolve);
                    Class<?> loaded = findLoadedClass(name);
                    if (loaded == null) loaded = findClass(name);
                    if (resolve) resolveClass(loaded);
                    return loaded;
                }
            }) {
                JSONObject identity = new JSONObject().put("profileKey", "generic")
                    .put("package", "VirtualDesktop.Android").put("status", "research").put("recipe", "vd-embedded-v5");
                ApplicationProfile profile = (ApplicationProfile) loader.loadClass(type.getName()).getConstructor(JSONObject.class)
                    .newInstance(new JSONObject().put("schema", 1).put("profile", identity));
                assertNotSame(type.getClassLoader(), profile.getClass().getClassLoader());
                assertEquals("VirtualDesktop.Android", profile.metadata().getString("package"));
                if (type == VdProfile.class) {
                    try {
                        profile.prepare(Path.of("unused.apk"), new JSONObject().put("manifest", new JSONObject().put("package", "other.app")), new byte[0], "other.app");
                        fail("Invalid input must still be rejected");
                    } catch (IllegalArgumentException expected) {
                        assertEquals("VD package differs", expected.getMessage());
                    }
                }
            }
        }
    }
}
