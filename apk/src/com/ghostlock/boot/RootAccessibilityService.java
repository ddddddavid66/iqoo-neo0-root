package com.ghostlock.boot;

import android.accessibilityservice.AccessibilityService;
import android.accessibilityservice.AccessibilityServiceInfo;
import android.view.accessibility.AccessibilityEvent;

/**
 * Fourth and last trigger path.
 *
 * <p>The other three all dead-end on this phone: BOOT_COMPLETED is delivered at
 * uptime 85.9s (past the 23-48s window), LOCKED_BOOT_COMPLETED is never
 * delivered at all, and a persisted JobScheduler record does not survive a
 * reboot here (dumpsys jobscheduler is empty for the package afterwards).
 *
 * <p>An accessibility service is bound by the system through AMS whenever it
 * starts, not through the boot-broadcast path, so the vendor autostart list has
 * no say. It also reconnects after every reboot as long as the user enabled it
 * once in settings.
 *
 * <p>The service does nothing with accessibility events; it only needs the
 * connection callback as a "the framework is up" signal.
 */
public class RootAccessibilityService extends AccessibilityService {

    @Override
    protected void onServiceConnected() {
        super.onServiceConnected();
        Launcher.log(this, "accessibility connected, uptime=" + Launcher.uptime() + "s");

        // Re-arm the job as well: belt and braces, in case the accessibility
        // binding happens outside the window on this boot.
        Launcher.scheduleBootJob(this);

        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Launcher.fireOnce(RootAccessibilityService.this, false, "accessibility");
                } catch (Throwable e) {
                    Launcher.log(RootAccessibilityService.this, "accessibility fire threw: " + e);
                }
            }
        }, "ghostlock-a11y");
        t.start();
    }

    @Override
    public void onAccessibilityEvent(AccessibilityEvent event) {
        // Not used.
    }

    @Override
    public void onInterrupt() {
        // Not used.
    }
}
