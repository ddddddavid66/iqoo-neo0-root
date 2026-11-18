package com.ghostlock.boot;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

/**
 * Foreground service that hosts the exploit.
 *
 * <p>The native payload runs for tens of seconds and keeps several hundred
 * threads alive while it sprays; a plain background service would be a candidate
 * for the low-memory killer exactly then. A foreground service plus a partial
 * wake lock is the minimum that survives that window without extra permissions.
 *
 * <p>The wake lock matters more than it looks: boot broadcasts often arrive
 * while the screen is still off, and the CPU going back to sleep mid-spray would
 * turn a would-be hit into a miss.
 */
public class RootService extends Service {

    public static final String ACTION_BOOT = "com.ghostlock.boot.action.BOOT";
    public static final String ACTION_MANUAL = "com.ghostlock.boot.action.MANUAL";
    public static final String EXTRA_REASON = "reason";
    public static final String EXTRA_FORCE = "force";

    private static final String CHANNEL = "ghostlock";
    private static final int NOTICE_ID = 0x676c;

    private PowerManager.WakeLock wakeLock;

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        startForeground(NOTICE_ID, buildNotice());

        final String action = intent == null || intent.getAction() == null
                ? ACTION_BOOT : intent.getAction();
        final boolean force = intent != null && intent.getBooleanExtra(EXTRA_FORCE, false);
        final String extra = intent == null ? null : intent.getStringExtra(EXTRA_REASON);
        final String reason = extra == null ? action : extra;

        Launcher.log(this, "service start: action=" + action + " force=" + force);
        acquireWakeLock();

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Launcher.fireOnce(RootService.this, force, reason);
                } catch (Throwable e) {
                    Launcher.log(RootService.this, "fire threw: " + e);
                } finally {
                    releaseWakeLock();
                    stopSelf();
                }
            }
        }, "ghostlock-fire");
        t.setDaemon(false);
        t.start();
        return START_NOT_STICKY;
    }

    private void acquireWakeLock() {
        if (wakeLock != null) {
            return;
        }
        try {
            PowerManager pm = (PowerManager) getSystemService(POWER_SERVICE);
            if (pm == null) {
                return;
            }
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "ghostlock:fire");
            wakeLock.setReferenceCounted(false);
            // The payload gives up on its own well before this; the timeout is
            // only here so a wedged kernel cannot pin the CPU awake forever.
            wakeLock.acquire(5 * 60 * 1000L);
        } catch (Exception e) {
            Launcher.log(this, "wakelock failed: " + e);
        }
    }

    private void releaseWakeLock() {
        try {
            if (wakeLock != null && wakeLock.isHeld()) {
                wakeLock.release();
            }
        } catch (Exception ignored) {
            // releasing a lock we no longer hold is not worth a crash
        }
        wakeLock = null;
    }

    @Override
    public void onDestroy() {
        releaseWakeLock();
        super.onDestroy();
    }

    private Notification buildNotice() {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
            if (nm != null && nm.getNotificationChannel(CHANNEL) == null) {
                NotificationChannel ch = new NotificationChannel(
                        CHANNEL, "GhostLock", NotificationManager.IMPORTANCE_LOW);
                ch.setShowBadge(false);
                nm.createNotificationChannel(ch);
            }
            b = new Notification.Builder(this, CHANNEL);
        } else {
            //noinspection deprecation
            b = new Notification.Builder(this);
        }
        //noinspection deprecation
        return b.setContentTitle("GhostLock")
                .setContentText("checking boot window…")
                .setSmallIcon(android.R.drawable.stat_notify_sync)
                .setOngoing(true)
                .build();
    }
}
