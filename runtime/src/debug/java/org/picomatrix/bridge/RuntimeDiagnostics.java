package org.picomatrix.bridge;

import android.content.Context;
import android.util.Log;
import android.graphics.Bitmap;
import android.opengl.EGL14;
import android.opengl.EGLConfig;
import android.opengl.EGLContext;
import android.opengl.EGLDisplay;
import android.opengl.EGLSurface;
import android.opengl.GLES30;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Optional, read-only managed UI snapshots in locally assembled research builds. */
public final class RuntimeDiagnostics {
    private static boolean started;
    public static synchronized void start(Context client) {
        if (started || !"org.picomatrix.bridge.vd".equals(client.getPackageName())) return;
        started = true;
        try {
            System.loadLibrary("matrixdiag");
            startNative(client);
        } catch (UnsatisfiedLinkError unavailable) {
            // The optional native probe is absent from ordinary debug builds.
            Log.d("MatrixDiag", "optional UI probe unavailable");
        }
    }
    private static native void startNative(Context client);

    /** Read one existing UI texture using a separate shared context and FBO. */
    private static void captureTexture(Context client, EGLDisplay display, EGLContext parent,
                                       int texture, int width, int height, int mode) {
        if (width < 1 || height < 1 || width > 4096 || height > 4096) return;
        EGLContext context = EGL14.EGL_NO_CONTEXT;
        EGLSurface surface = EGL14.EGL_NO_SURFACE;
        int[] fbo = {0};
        boolean current = false;
        try {
            int[] configId = new int[1], count = new int[1];
            if (!EGL14.eglQueryContext(display, parent, EGL14.EGL_CONFIG_ID, configId, 0))
                throw new IllegalStateException("query shared context");
            EGLConfig[] configs = new EGLConfig[128];
            if (!EGL14.eglChooseConfig(display, new int[]{EGL14.EGL_CONFIG_ID, configId[0], EGL14.EGL_NONE},
                    0, configs, 0, configs.length, count, 0) || count[0] < 1)
                throw new IllegalStateException("select shared config");
            context = EGL14.eglCreateContext(display, configs[0], parent,
                    new int[]{EGL14.EGL_CONTEXT_CLIENT_VERSION, 3, EGL14.EGL_NONE}, 0);
            if (context == EGL14.EGL_NO_CONTEXT) throw new IllegalStateException("create shared context");
            surface = EGL14.eglCreatePbufferSurface(display, configs[0],
                    new int[]{EGL14.EGL_WIDTH, 1, EGL14.EGL_HEIGHT, 1, EGL14.EGL_NONE}, 0);
            if (surface == EGL14.EGL_NO_SURFACE) throw new IllegalStateException("create probe surface");
            current = EGL14.eglMakeCurrent(display, surface, surface, context);
            if (!current) throw new IllegalStateException("make probe current");
            if (!GLES30.glIsTexture(texture)) throw new IllegalStateException("UI texture not shared");
            GLES30.glGenFramebuffers(1, fbo, 0);
            GLES30.glBindFramebuffer(GLES30.GL_FRAMEBUFFER, fbo[0]);
            GLES30.glFramebufferTexture2D(GLES30.GL_FRAMEBUFFER, GLES30.GL_COLOR_ATTACHMENT0,
                    GLES30.GL_TEXTURE_2D, texture, 0);
            int status = GLES30.glCheckFramebufferStatus(GLES30.GL_FRAMEBUFFER);
            if (status != GLES30.GL_FRAMEBUFFER_COMPLETE) {
                Log.i("MatrixDiag", "UI capture framebuffer status=" + status);
                return;
            }
            ByteBuffer pixels = ByteBuffer.allocateDirect(width * height * 4).order(ByteOrder.nativeOrder());
            GLES30.glReadPixels(0, 0, width, height, GLES30.GL_RGBA, GLES30.GL_UNSIGNED_BYTE, pixels);
            int error = GLES30.glGetError();
            if (error != GLES30.GL_NO_ERROR) {
                Log.i("MatrixDiag", "UI capture GL error=" + error);
                return;
            }
            Bitmap bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888);
            bitmap.copyPixelsFromBuffer(pixels);
            // GL origin is bottom-left. Preserve raw orientation for research provenance.
            File researchDir = client.getExternalFilesDir(null);
            if (researchDir == null) throw new IllegalStateException("research output unavailable");
            try (FileOutputStream out = new FileOutputStream(new File(researchDir,
                    "matrix-ui-" + android.os.Process.myPid() + (mode == 0 ? "-texture.png" : "-white-texture.png")))) {
                bitmap.compress(Bitmap.CompressFormat.PNG, 100, out);
            } finally { bitmap.recycle(); }
            Log.i("MatrixDiag", "UI texture captured mode=" + mode + " width=" + width + " height=" + height);
        } catch (Exception failure) {
            Log.i("MatrixDiag", "UI texture capture failed: " + failure.getClass().getSimpleName());
        } finally {
            if (current) {
                GLES30.glDeleteFramebuffers(1, fbo, 0);
                EGL14.eglMakeCurrent(display, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_SURFACE, EGL14.EGL_NO_CONTEXT);
            }
            if (surface != EGL14.EGL_NO_SURFACE) EGL14.eglDestroySurface(display, surface);
            if (context != EGL14.EGL_NO_CONTEXT) EGL14.eglDestroyContext(display, context);
        }
    }
}
