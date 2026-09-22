package org.picomatrix.bridge.installer.android;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/** Explicit PendingIntent target; no exported callback surface. */
public final class InstallResultReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context,Intent intent) {
        // Receipt handling is bounded; APK hashing and account work use the worker queue.
        new MatrixInstaller(context).receive(intent);
    }
}
