package com.ghostlock.boot;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.method.ScrollingMovementMethod;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/**
 * Manual console: shows the current state and lets you fire by hand.
 *
 * <p>Two buttons, because on this phone there are exactly two useful manual
 * actions: reload the state, and take a shot right now. The manual shot bypasses
 * the uptime window on purpose — it exists for the case where the boot broadcast
 * arrived too late and you already rebooted the phone yourself.
 */
public class MainActivity extends Activity {

    private TextView status;
    private TextView log;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        // Without an explicit background the theme's white wins and the white
        // title disappears into it — the app looks blank on first launch.
        root.setBackgroundColor(Color.parseColor("#101418"));
        int pad = (int) (16 * getResources().getDisplayMetrics().density);
        root.setPadding(pad, pad, pad, pad);

        TextView title = new TextView(this);
        title.setText("GhostLock Boot");
        title.setTextSize(20f);
        title.setTextColor(Color.WHITE);
        root.addView(title);

        status = new TextView(this);
        status.setTextSize(13f);
        status.setTextColor(Color.parseColor("#9BE89B"));
        status.setPadding(0, pad / 2, 0, pad / 2);
        root.addView(status);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.VERTICAL);

        Button refresh = new Button(this);
        refresh.setText("刷新");
        refresh.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                render();
            }
        });
        bar.addView(refresh);

        Button fire = new Button(this);
        fire.setText("立即发射（忽略窗口）");
        fire.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent svc = new Intent(MainActivity.this, RootService.class);
                svc.setAction(RootService.ACTION_MANUAL);
                svc.putExtra(RootService.EXTRA_FORCE, true);
                svc.putExtra(RootService.EXTRA_REASON, "manual");
                try {
                    startForegroundService(svc);
                    Launcher.log(MainActivity.this, "manual fire requested");
                } catch (Exception e) {
                    // Android 12+ refuses a foreground-service start from the
                    // background; from an Activity this should never happen,
                    // but a silent crash here would look like "the button does
                    // nothing".
                    Launcher.log(MainActivity.this, "manual fire refused: " + e);
                }
                ui.postDelayed(new Runnable() {
                    @Override
                    public void run() {
                        render();
                    }
                }, 1500);
            }
        });
        bar.addView(fire);

        Button reset = new Button(this);
        reset.setText("重置本 boot 标记");
        reset.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Without this there is no way to retry by hand after a miss:
                // the one-shot guard would keep refusing until the next reboot.
                java.io.File mark = new java.io.File(Launcher.workDir(MainActivity.this), ".fired_boot");
                //noinspection ResultOfMethodCallIgnored
                boolean gone = mark.delete() || !mark.exists();
                Launcher.log(MainActivity.this, "boot marker reset: " + gone);
                render();
            }
        });
        bar.addView(reset);

        // --- adbd bridge controls -------------------------------------------
        //
        // The exploit cannot run in this process (untrusted_app + Seccomp=2),
        // so the real shot goes through the phone's own adbd. These three
        // buttons cover the one-time setup and let you sanity-check it without
        // rebooting.

        Button probe = new Button(this);
        probe.setText("测试 adbd 通道");
        probe.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                final AdbBridge.Result r = AdbBridge.probe(MainActivity.this);
                Launcher.log(MainActivity.this, "probe: " + r.detail);
                render();
            }
        });
        bar.addView(probe);

        Button copyKey = new Button(this);
        copyKey.setText("复制 adb 公钥");
        copyKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    String line = AdbBridge.publicKeyLine(MainActivity.this);
                    ClipboardManager cm = (ClipboardManager)
                            getSystemService(CLIPBOARD_SERVICE);
                    if (cm != null) {
                        cm.setPrimaryClip(ClipData.newPlainText("ghostlock adbkey", line));
                    }
                    Launcher.log(MainActivity.this, "adb public key copied: " + line);
                } catch (Exception e) {
                    Launcher.log(MainActivity.this, "public key export failed: " + e);
                }
                render();
            }
        });
        bar.addView(copyKey);

        Button registerKey = new Button(this);
        registerKey.setText("登记公钥（需要 root）");
        registerKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // Runs while some root is still alive — either the PC-side shot
                // or a previous boot — and makes the bridge self-sufficient from
                // then on. KernelSU may pop its own grant dialog.
                String out = AdbBridge.registerKey(MainActivity.this);
                Launcher.log(MainActivity.this, "register key: " + out);
                render();
            }
        });
        bar.addView(registerKey);
        root.addView(bar);

        log = new TextView(this);
        log.setTextSize(11f);
        log.setTextColor(Color.parseColor("#DDDDDD"));
        log.setGravity(Gravity.TOP | Gravity.START);
        log.setMovementMethod(new ScrollingMovementMethod());

        ScrollView scroller = new ScrollView(this);
        scroller.addView(log);
        root.addView(scroller, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);

        // Unpack the payload up front so the status page tells the truth on the
        // first launch, and so the boot path never spends time on file copies
        // inside the 23s window.
        try {
            Launcher.prepare(this);
        } catch (Exception e) {
            Launcher.log(this, "prepare on launch failed: " + e);
        }
        // Arm the persisted job once. It then re-arms itself across every reboot
        // without needing this activity or any boot broadcast.
        Launcher.scheduleBootJob(this);

        // Probe the adbd bridge on every launch. Opening the app is the normal
        // way to check whether the bridge is wired up, and doing it off the UI
        // thread keeps the screen responsive even when adbd is unreachable.
        new Thread(new Runnable() {
            @Override
            public void run() {
                final AdbBridge.Result r = AdbBridge.probe(MainActivity.this);
                Launcher.log(MainActivity.this, "auto probe: " + r.detail);
                ui.post(new Runnable() {
                    @Override
                    public void run() {
                        render();
                    }
                });
            }
        }, "bridge-probe").start();

        render();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // Coming back from the launcher is the normal way to check whether the
        // boot shot worked, so refresh rather than showing a stale snapshot.
        render();
    }

    private void render() {
        status.setText(Launcher.status(this));
        String tail = tailFrom(new java.io.File(Launcher.workDir(this), "app.log"), 40);
        log.setText(tail);
    }

    private String tailFrom(java.io.File f, int lines) {
        String all = Launcher.readText(f);
        if (all.isEmpty()) {
            return "(还没有日志)";
        }
        String[] parts = all.split("\n");
        int from = Math.max(0, parts.length - lines);
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < parts.length; i++) {
            sb.append(parts[i]).append('\n');
        }
        return sb.toString();
    }
}
