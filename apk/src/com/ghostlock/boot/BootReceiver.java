package com.ghostlock.boot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * Kicks the payload off after boot.
 *
 * <p>BOOT_COMPLETED only arrives once the framework is up, which on this phone
 * is right around the 25-48s uptime window the exploit needs. Several vendor
 * specific extra actions are listed in the manifest because OriginOS drops the
 * plain AOSP broadcast for apps it has not whitelisted in its own startup
 * manager.
 *
 * <p>MY_PACKAGE_REPLACED is here so that reinstalling during bring-up immediately
 * exercises the same code path without a reboot.
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context c, Intent intent) {
        String action = intent == null || intent.getAction() == null
                ? "unknown" : intent.getAction();
        Launcher.log(c, "boot broadcast: " + action);

        // Re-arm the persisted job first. This broadcast may well arrive after
        // the window has closed (measured: uptime 85.9s on this phone), in which
        // case the shot below is skipped and the job is what carries the next
        // boot. Scheduling is idempotent — it replaces the existing record.
        Launcher.scheduleBootJob(c);

        Intent svc = new Intent(c, RootService.class);
        svc.setAction(RootService.ACTION_BOOT);
        svc.putExtra(RootService.EXTRA_REASON, action);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                c.startForegroundService(svc);
            } else {
                c.startService(svc);
            }
        } catch (Exception e) {
            Launcher.log(c, "cannot start service: " + e);
        }
    }
}
