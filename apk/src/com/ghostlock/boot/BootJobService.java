package com.ghostlock.boot;

import android.app.job.JobParameters;
import android.app.job.JobService;

/**
 * Trigger path that survives vendor boot-broadcast blocking.
 *
 * <p>OriginOS drops BOOT_COMPLETED into this app at uptime ~86s (too late for
 * the 23-48s window) and does not deliver LOCKED_BOOT_COMPLETED at all. A
 * persisted JobScheduler job takes a different route entirely: the job record
 * lives in JobSchedulerService's own store, that service reloads it on every
 * boot, and it schedules the work itself — no broadcast has to reach the app,
 * so the vendor's autostart list never gets a say.
 *
 * <p>setPersisted(true) is what makes the record survive a reboot; it requires
 * RECEIVE_BOOT_COMPLETED, which the manifest already declares.
 */
public class BootJobService extends JobService {

    @Override
    public boolean onStartJob(final JobParameters params) {
        Launcher.log(this, "boot job fired: id=" + params.getJobId()
                + " uptime=" + Launcher.uptime() + "s");
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    Launcher.fireOnce(BootJobService.this, false, "boot-job");
                } catch (Throwable e) {
                    Launcher.log(BootJobService.this, "boot job threw: " + e);
                } finally {
                    jobFinished(params, false);
                }
            }
        }, "ghostlock-job");
        t.start();
        return true; // keep the wakelock while the thread runs
    }

    @Override
    public boolean onStopJob(JobParameters params) {
        // The payload is not resumable; let the next boot schedule a fresh one.
        return false;
    }
}
