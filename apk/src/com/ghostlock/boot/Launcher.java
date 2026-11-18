package com.ghostlock.boot;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.os.SystemClock;
import android.system.Os;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.Map;

/**
 * Runs the GhostLock payload from inside this app, with no PC and no adb.
 *
 * <p>The payload is shipped as {@code lib/arm64-v8a/libghostlock.so} because on
 * Android 10+ an app cannot execute files it owns ({@code app_data_file}); only
 * the unpacked native-library directory ({@code apk_data_file}) is executable.
 * The same trick applies to ksud, which the embedded root script has to be able
 * to run for the KernelSU late-load.
 *
 * <p>The exploit only lands in a narrow window right after boot, so every entry
 * point funnels through {@link #fireOnce}: one shot per boot, gated on uptime.
 */
public final class Launcher {

    public static final String TAG = "GhostLockBoot";

    /** Subdirectory under filesDir that becomes $HOME for the payload. */
    private static final String WORK = "gl";

    /**
     * Uptime window, seconds. Outside this the shot either misses or panics.
     *
     * <p>{@code WIN_LOW} is 30, not 23. Measured hits cluster at uptime 31–71s,
     * and anything fired before ~25s buys a kernel panic instead of a root:
     * on 2026-11-17 the accessibility service connected at 22.5s, the shot went
     * out at 23.0s, and the phone went down hard (adbd connection dropped with
     * a bare "closed", device disappeared from USB). The bridge itself was fine
     * that time — probe reached the shell domain at 23.1s — so the only thing
     * wrong was firing too early.
     *
     * <p>The PC-side watchdog has always used {@code -MinUptime 25} and lands
     * near 30s, which is why it succeeds where this used to fail.
     */
    public static final int WIN_LOW = 30;
    public static final int WIN_HIGH = 48;

    /**
     * Latest uptime at which to keep polling for adbd before giving up on the
     * bridge. The exploit needs about 10s, so stopping here still leaves room
     * to finish inside WIN_HIGH.
     */
    private static final int BRIDGE_READY_DEADLINE = 36;

    /** Manager package whose libksud.so performs the late-load. */
    private static final String MANAGER_PKG = "com.sukisu.ultra";
    private static final String KMI = "android13-5.15";

    private Launcher() {
    }

    // ------------------------------------------------------------------ paths

    /**
     * Where the payload's $HOME lives.
     *
     * <p>Device-protected storage, always — including after the user unlocks.
     * The boot shot is triggered by LOCKED_BOOT_COMPLETED, which arrives while
     * credential-encrypted storage (/data/user/0) is still unavailable, so the
     * work dir has to sit in /data/user_de/0. Using one path in both modes also
     * keeps the one-shot marker and the logs meaningful across a boot.
     */
    public static File workDir(Context c) {
        Context storage = c;
        try {
            Context dp = c.createDeviceProtectedStorageContext();
            if (dp != null) {
                storage = dp;
            }
        } catch (Exception e) {
            Log.w(TAG, "device-protected storage unavailable, falling back: " + e);
        }
        File d = new File(storage.getFilesDir(), WORK);
        if (!d.isDirectory() && !d.mkdirs() && !d.isDirectory()) {
            Log.w(TAG, "cannot create work dir " + d);
        }
        return d;
    }

    private static File libFile(Context c, String name) {
        ApplicationInfo ai = c.getApplicationInfo();
        return new File(ai.nativeLibraryDir, name);
    }

    public static File payloadBinary(Context c) {
        return libFile(c, "libghostlock.so");
    }

    public static File ksudBinary(Context c) {
        return libFile(c, "libksud.so");
    }

    // -------------------------------------------------------------- utilities

    public static void log(Context c, String msg) {
        String line = stamp() + " " + msg;
        Log.i(TAG, line);
        Writer w = null;
        try {
            File f = new File(workDir(c), "app.log");
            w = new OutputStreamWriter(new FileOutputStream(f, true), StandardCharsets.UTF_8);
            w.write(line);
            w.write("\n");
        } catch (IOException e) {
            Log.w(TAG, "append log failed: " + e);
        } finally {
            closeQuietly(w);
        }
    }

    private static String stamp() {
        return new SimpleDateFormat("MM-dd HH:mm:ss", Locale.US).format(new Date());
    }

    /**
     * Seconds since boot, including suspend time.
     *
     * <p>Read through {@link SystemClock#elapsedRealtime()} instead of
     * /proc/uptime: on Android 14 that proc file carries the proc_uptime label
     * and untrusted_app has no read rule for it, so opening it yields an empty
     * stream with no audit denial. That showed up as "uptime: -1.0s" in the UI
     * while boot_id (a different label) read fine. CLOCK_BOOTTIME is the same
     * quantity /proc/uptime reports, so the window constants stay meaningful.
     */
    public static double uptime() {
        return SystemClock.elapsedRealtime() / 1000.0;
    }

    /** /proc/sys/kernel/random/boot_id, or "" when unreadable. */
    public static String bootId() {
        BufferedReader r = null;
        try {
            r = new BufferedReader(new InputStreamReader(
                    new FileInputStream("/proc/sys/kernel/random/boot_id"), StandardCharsets.US_ASCII));
            String s = r.readLine();
            return s == null ? "" : s.trim();
        } catch (Exception e) {
            return "";
        } finally {
            closeQuietly(r);
        }
    }

    public static String readText(File f) {
        if (!f.isFile()) {
            return "";
        }
        BufferedReader r = null;
        try {
            r = new BufferedReader(new InputStreamReader(
                    new FileInputStream(f), StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (IOException e) {
            return "";
        } finally {
            closeQuietly(r);
        }
    }

    private static void writeText(File f, String text) throws IOException {
        FileOutputStream out = new FileOutputStream(f, false);
        try {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } finally {
            out.close();
        }
    }

    private static void closeQuietly(java.io.Closeable c) {
        if (c != null) {
            try {
                c.close();
            } catch (IOException ignored) {
                // nothing useful to do
            }
        }
    }

    // ---------------------------------------------------------------- staging

    /**
     * Materialises everything the embedded root script expects under $HOME.
     *
     * <p>Returns the path of {@code ksud} the script should find first, or ""
     * when no ksud could be provided at all.
     */
    public static String prepare(Context c) throws IOException {
        File w = workDir(c);
        copyAsset(c, "profile.bin", new File(w, "profile.bin"));
        copyAsset(c, "vrpatch.ko", new File(w, "vrpatch.ko"));

        writeText(new File(w, ".gl_ksu_pkg"), MANAGER_PKG + "\n");
        writeText(new File(w, ".gl_kmi"), KMI + "\n");

        // The root script prefers $HOME/ksud over everything else. A symlink is
        // the only way to satisfy that while keeping the real file in the
        // executable native-library directory.
        File ksud = ksudBinary(c);
        File link = new File(w, "ksud");
        if (!ksud.isFile()) {
            log(c, "prepare: libksud.so missing from " + ksud.getParent());
            return "";
        }
        // File.delete() removes the link itself, never the target, so this is
        // safe whether the path is a leftover symlink or a plain file.
        //noinspection ResultOfMethodCallIgnored
        link.delete();
        try {
            Os.symlink(ksud.getAbsolutePath(), link.getAbsolutePath());
            log(c, "prepare: ksud -> " + ksud.getAbsolutePath());
        } catch (Exception e) {
            // Falling back is fine: the root script also scans /data/app for a
            // libksud.so, and ours is under exactly that name.
            log(c, "prepare: symlink failed (" + e + "), relying on /data/app scan");
        }
        return link.getAbsolutePath();
    }

    private static void copyAsset(Context c, String name, File dst) throws IOException {
        if (dst.isFile() && dst.length() > 0) {
            return;
        }
        InputStream in = c.getAssets().open(name);
        FileOutputStream out = new FileOutputStream(dst, false);
        try {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
        } finally {
            closeQuietly(in);
            out.close();
        }
    }

    // ------------------------------------------------------------------- job

    /** Id of the persisted boot job. Stable across versions on purpose. */
    public static final int BOOT_JOB_ID = 0x676c01;

    /**
     * Registers the persisted job that triggers a shot after every boot.
     *
     * <p>This is the only trigger path that originOS does not police. It drops
     * BOOT_COMPLETED into the app at uptime ~86s (past the window) and never
     * delivers LOCKED_BOOT_COMPLETED, but a persisted job record lives inside
     * JobSchedulerService: that service reloads it at boot and dispatches the
     * work itself, so nothing has to reach the app through a broadcast.
     *
     * <p>setMinimumLatency(15s) places the run roughly at uptime 30-45s on this
     * phone — JobSchedulerService restores persisted jobs once the framework is
     * far enough along that elapsed-realtime is already past 15s. The deadline
     * keeps a low-priority deferral from pushing it out of the window entirely.
     */
    public static void scheduleBootJob(Context c) {
        try {
            android.app.job.JobScheduler js =
                    (android.app.job.JobScheduler) c.getSystemService(Context.JOB_SCHEDULER_SERVICE);
            if (js == null) {
                log(c, "schedule: no JobScheduler");
                return;
            }
            android.content.ComponentName cn =
                    new android.content.ComponentName(c, BootJobService.class);
            android.app.job.JobInfo job = new android.app.job.JobInfo.Builder(BOOT_JOB_ID, cn)
                    .setPersisted(true)
                    .setMinimumLatency(15_000L)
                    .setOverrideDeadline(90_000L)
                    .build();
            int rc = js.schedule(job);
            log(c, "schedule boot job rc=" + rc);
        } catch (Exception e) {
            log(c, "schedule boot job failed: " + e);
        }
    }

    // ------------------------------------------------------------------- fire

    /**
     * The single entry point that actually launches the exploit.
     *
     * <p>Rules encoded here, all of them learned the hard way on this phone:
     * <ul>
     *   <li>At most one shot per boot. A second shot lands W2 on a kernel that
     *       already carries the late-loaded module and panics ~60s later, which
     *       also destroys the root the first shot had just produced.</li>
     *   <li>Never fire above {@link #WIN_HIGH}. Shots at uptime 66s and 77s
     *       both killed the kernel mid-exploit.</li>
     *   <li>Wait out the lower bound rather than shooting early.</li>
     * </ul>
     *
     * @param force skip the uptime window check (manual trigger only)
     * @return true when a shot was actually taken
     */
    public static synchronized boolean fireOnce(Context c, boolean force, String reason) {
        File w = workDir(c);
        String boot = bootId();
        File mark = new File(w, ".fired_boot");

        // Wait for the window BEFORE touching any guard.
        //
        // 2026-11-17 00:15 boot: a trigger at uptime ~20.5s recorded the guard
        // timestamp and then went to sleep waiting for 23s. The accessibility
        // service arrived at 21.4s, found that seconds-fresh timestamp and
        // rejected itself with "fired 0s ago" — and so did every later trigger
        // for the next two minutes. Nothing ever fired even though all four
        // entry points worked exactly as designed.
        double up = uptime();
        if (up >= 0 && !force && up < WIN_LOW) {
            long ms = (long) ((WIN_LOW - up) * 1000L);
            log(c, "waiting " + ms + "ms for uptime " + WIN_LOW + "s (now " + fmt(up) + "s)");
            try {
                Thread.sleep(ms);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
            up = uptime();
        }

        String prev = readText(mark).trim();
        if (!boot.isEmpty() && boot.equals(prev)) {
            log(c, "skip (" + reason + "): already fired on boot " + boot);
            return false;
        }

        // Second guard, for when /proc/sys/kernel/random/boot_id is unreadable
        // and the marker above degrades into "fire on every call".
        //
        // The value is stored as "<boot_id> <elapsedRealtime_ms>", and the
        // boot_id half is what makes it correct. elapsedRealtime restarts at
        // zero on every boot, so a bare millisecond value left over from the
        // previous boot reads as "fired 0s ago" whenever this boot's trigger
        // lands at a similar uptime — which it does at every single boot,
        // because the triggers are driven by boot timeline rather than by
        // wall clock.
        long now = SystemClock.elapsedRealtime();
        File tsMark = new File(w, ".last_fire");
        String ts = readText(tsMark).trim();
        if (!boot.isEmpty() && !ts.isEmpty()) {
            int sp = ts.indexOf(' ');
            if (sp > 0 && boot.equals(ts.substring(0, sp))) {
                try {
                    long last = Long.parseLong(ts.substring(sp + 1).trim());
                    if (now > last && now - last < 120_000L) {
                        log(c, "skip (" + reason + "): fired " + ((now - last) / 1000)
                                + "s ago on this boot, refusing a repeat shot");
                        return false;
                    }
                } catch (NumberFormatException ignored) {
                    // unreadable marker: treat as a first run
                }
            }
        }
        try {
            writeText(tsMark, boot + " " + now + "\n");
        } catch (IOException e) {
            log(c, "warning: cannot record time guard: " + e);
        }

        if (up < 0) {
            log(c, "skip (" + reason + "): cannot read uptime");
            return false;
        }
        if (force) {
            log(c, "window check bypassed (force), uptime=" + fmt(up) + "s");
        } else if (up > WIN_HIGH) {
            log(c, "skip (" + reason + "): uptime=" + fmt(up) + "s past window "
                    + WIN_LOW + "-" + WIN_HIGH + "s; reboot and let it fire on boot");
            return false;
        }

        // Stage first, mark second: a failed prepare (missing ksud, unwritable
        // files dir) must not burn the rest of this boot, because the marker is
        // what stops a retry.
        String ksudPath;
        try {
            ksudPath = prepare(c);
        } catch (IOException e) {
            log(c, "abort: prepare failed: " + e);
            return false;
        }

        // Record the boot BEFORE the shot: a successful shot can take the
        // kernel down and this process never gets to write the marker after.
        if (!boot.isEmpty()) {
            try {
                writeText(mark, boot + "\n");
            } catch (IOException e) {
                log(c, "warning: cannot record boot marker: " + e);
            }
        }

        log(c, "firing (" + reason + ") uptime=" + fmt(uptime()) + "s boot=" + boot);

        // Two ways to reach the kernel, tried in order of expected success.
        //
        // 1. Through adbd. adbd already runs as its own domain and forks the
        //    "shell:" service as u:r:shell:s0 with Seccomp=0 and a readable
        //    /sys/fs/selinux/enforce — the exact environment where this exploit
        //    has been landing on this phone. The app only needs to connect to
        //    127.0.0.1:5555 and answer an RSA challenge.
        // 2. In-process, as a fallback when the bridge is not set up. This is
        //    the path that keeps failing in prepare_kernel_page, so it is a
        //    safety net rather than the plan.
        int rc;
        String verdict;
        // adbd finishes coming up a few seconds after the framework does. At
        // uptime 22s (the moment the accessibility service connects) its TCP
        // port accepts the connection and then closes it without sending a
        // single byte, which reads as "bridge unusable" and silently drops the
        // whole shot onto the in-process path. So poll until adbd actually
        // answers, and keep enough of the window left to run the exploit:
        // reliable hits on this phone fired around uptime 31s, window ends 48s.
        AdbBridge.Result ready = AdbBridge.probe(c);
        while (!ready.authed && uptime() < BRIDGE_READY_DEADLINE) {
            log(c, "adbd not ready (" + ready.detail + "), retrying in 1.5s");
            try {
                Thread.sleep(1500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            ready = AdbBridge.probe(c);
        }
        log(c, "bridge ready at uptime=" + fmt(uptime()) + "s (" + ready.detail + ")");

        AdbBridge.Result br = ready.authed ? AdbBridge.fire(c) : ready;
        // A bridge that authenticated but could not find the script (fresh
        // install, /data/local/tmp wiped) is a staging problem, so the in-app
        // path still deserves its chance. A stream that died after the script
        // started is the opposite case and must NOT retry: that usually means
        // the kernel went down under the payload, and a second shot on the same
        // boot is what takes the whole system with it.
        boolean bridgeUsable = br.authed
                && !br.output.contains("No such file")
                && !br.output.contains("__RC__=127");
        if (bridgeUsable) {
            rc = br.exitCode;
            verdict = verdictFromBridge(br.output);
            log(c, "bridge ran the exploit (" + br.elapsedMs + "ms)");
        } else {
            log(c, "bridge unusable (" + br.detail + "), running in-app payload");
            rc = exec(c, w, ksudPath);
            verdict = verdictFromKsuLog(readText(new File(w, "ksu.log")));
        }

        log(c, "payload exited rc=" + rc + " -> " + verdict
                + " uptime=" + fmt(uptime()) + "s");
        return true;
    }

    /**
     * Reads the verdict out of what the bridge command printed.
     *
     * <p>Two markers matter: {@code __RC__=} carries glrun.sh's exit status and
     * everything after {@code __LOG__=} is a tail of the newest native log. The
     * KSU late-load line is what actually proves root went in.
     */
    private static String verdictFromBridge(String output) {
        String text = output == null ? "" : output;
        if (text.contains("KernelSU module loaded")) {
            return "late-load OK (shell domain)";
        }
        if (text.contains("root script start")) {
            return "root script ran, late-load did NOT finish (shell domain)";
        }
        if (text.contains("heap spray failed")) {
            return "heap spray failed (shell domain)";
        }
        if (text.contains("__LOG__=")) {
            return "shell domain ran, no KSU verdict in log tail";
        }
        if (text.trim().isEmpty()) {
            return "shell domain returned nothing";
        }
        return "shell domain ran, verdict unclear";
    }

    /** Same ladder as {@link #verdictFromBridge}, for the in-process ksu.log. */
    private static String verdictFromKsuLog(String ksu) {
        if (ksu.contains("KernelSU module loaded")) {
            return "late-load OK";
        }
        if (ksu.contains("root script start")) {
            return "root script ran, late-load did NOT finish";
        }
        if (!ksu.isEmpty()) {
            return "partial ksu log";
        }
        return "no root script output";
    }

    private static int exec(Context c, File w, String ksudPath) {
        File bin = payloadBinary(c);
        if (!bin.isFile()) {
            log(c, "abort: payload missing at " + bin);
            return -1;
        }
        File profile = new File(w, "profile.bin");
        File vrpatch = new File(w, "vrpatch.ko");
        File ksuLog = new File(w, "ksu.log");
        File nativeLog = new File(w, "native.log");

        ProcessBuilder pb = new ProcessBuilder(
                bin.getAbsolutePath(),
                "--load-prebuilt-profile", profile.getAbsolutePath(),
                "--force-attack");
        pb.directory(w);
        pb.redirectErrorStream(true);
        pb.redirectOutput(ProcessBuilder.Redirect.appendTo(nativeLog));

        Map<String, String> env = pb.environment();
        env.put("HOME", w.getAbsolutePath());
        env.put("TMPDIR", w.getAbsolutePath());
        env.put("GHOSTLOCK_HOME", w.getAbsolutePath());
        env.put("GHOSTLOCK_VRPATCH_KO", vrpatch.getAbsolutePath());
        env.put("GHOSTLOCK_KSU_LOG", ksuLog.getAbsolutePath());
        // 1 = late-load and leave SELinux enforcing. 0 would flip it permissive,
        // and W1 (writing selinux_enforcing) kills this kernel outright.
        env.put("GHOSTLOCK_KSU_ENFORCE", "1");
        if (!ksudPath.isEmpty()) {
            env.put("GHOSTLOCK_KSUD", ksudPath);
        }

        try {
            Process p = pb.start();
            int rc = p.waitFor();
            dumpNativeTail(c, nativeLog);
            return rc;
        } catch (IOException e) {
            log(c, "exec failed: " + e);
            return -1;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return -1;
        }
    }

    /**
     * Mirrors the tail of native.log into logcat.
     *
     * <p>filesDir is unreadable from adb on an unrooted phone, so without this
     * the only way to see why the payload bailed is to have root already —
     * which is exactly what we are trying to obtain. Lines are chunked because
     * logcat truncates entries around 4 KB.
     */
    private static void dumpNativeTail(Context c, File nativeLog) {
        String all = readText(nativeLog);
        if (all.isEmpty()) {
            log(c, "native.log is empty");
            return;
        }
        String[] lines = all.split("\n");
        int from = Math.max(0, lines.length - 120);
        StringBuilder chunk = new StringBuilder();
        for (int i = from; i < lines.length; i++) {
            String line = lines[i];
            if (chunk.length() + line.length() > 3000) {
                Log.i(TAG, "native| " + chunk);
                chunk.setLength(0);
            }
            chunk.append(line).append('\n');
        }
        if (chunk.length() > 0) {
            Log.i(TAG, "native| " + chunk);
        }
    }

    private static String fmt(double v) {
        return String.format(Locale.US, "%.1f", v);
    }

    /** Human-readable one-screen status for the activity. */
    public static String status(Context c) {
        File w = workDir(c);
        StringBuilder sb = new StringBuilder();
        sb.append("uptime      : ").append(fmt(uptime())).append("s\n");
        sb.append("window      : ").append(WIN_LOW).append("-").append(WIN_HIGH).append("s\n");
        sb.append("boot_id     : ").append(bootId()).append('\n');
        sb.append("fired boot  : ").append(orDash(readText(new File(w, ".fired_boot")).trim())).append('\n');
        sb.append("payload     : ").append(payloadBinary(c).isFile() ? "ok" : "MISSING").append('\n');
        sb.append("ksud        : ").append(ksudBinary(c).isFile() ? "ok" : "MISSING").append('\n');
        sb.append("profile.bin : ").append(new File(w, "profile.bin").isFile() ? "ok" : "missing").append('\n');
        sb.append("vrpatch.ko  : ").append(new File(w, "vrpatch.ko").isFile() ? "ok" : "missing").append('\n');
        sb.append("work dir    : ").append(w.getAbsolutePath()).append('\n');
        return sb.toString();
    }

    private static String orDash(String s) {
        return s == null || s.isEmpty() ? "-" : s;
    }
}
