#!/bin/bash
# Install the APK and click through vivo's "external source" prompt.
# The prompt is a separate activity (PackageInterceptActivity) that appears a
# couple of seconds after `pm install` starts and blocks the install until
# somebody presses 继续安装 — so watch the window focus and tap it.
set -u
S=10CE5P1A4G001PA
APK=/data/local/tmp/gl.apk

adb -s "$S" shell "pm install -r -d $APK" > /tmp/pm-install.log 2>&1 &
PM_PID=$!

for i in $(seq 1 30); do
    focus=$(adb -s "$S" shell "dumpsys window 2>/dev/null | grep mCurrentFocus | head -1" | tr -d '\r')
    if echo "$focus" | grep -q "packageinstaller"; then
        echo "[$i] prompt detected, tapping"
        adb -s "$S" shell "input tap 620 1755"
        sleep 3
        # Some builds chain a second confirmation page.
        focus2=$(adb -s "$S" shell "dumpsys window 2>/dev/null | grep mCurrentFocus | head -1" | tr -d '\r')
        if echo "$focus2" | grep -q "packageinstaller"; then
            echo "[$i] second page, tapping again"
            adb -s "$S" shell "input keyevent 66"
        fi
    fi
    if ! kill -0 $PM_PID 2>/dev/null; then
        echo "[$i] pm install returned"
        break
    fi
    sleep 1
done

wait $PM_PID 2>/dev/null
echo "=== pm output ==="
cat /tmp/pm-install.log
echo "=== lastUpdateTime ==="
adb -s "$S" shell "dumpsys package com.ghostlock.boot | grep lastUpdateTime | head -1"
