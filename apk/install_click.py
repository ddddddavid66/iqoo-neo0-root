#!/usr/bin/env python3
"""Install the APK and click through vivo's PackageInterceptActivity.

vivo routes every adb install through its own "外部来源应用" prompt, which
blocks the install until somebody presses 继续安装. `settings put global
verifier_verify_adb_installs 0` does not disable it, and keyevent does not
activate the button — it only responds to a real touch.

So: keep tapping the button area on a short cycle while `pm install` runs. The
tap is harmless before the prompt appears and lands on 继续安装 once it does.
The button bounds are read back from uiautomator so the coordinates are not
guessed from a screenshot.
"""
import re
import subprocess
import sys
import threading
import time

ADB = r"D:\David\study2222\tool\platform-tools\adb.exe"
SERIAL = "10CE5P1A4G001PA"
APK = "/data/local/tmp/gl.apk"


def adb(*args, timeout=25):
    return subprocess.run([ADB, "-s", SERIAL, *args],
                          capture_output=True, text=True, timeout=timeout)


def focus():
    out = adb("shell", "dumpsys window 2>/dev/null | grep mCurrentFocus | head -1").stdout
    return out.strip()


def button_bounds(label):
    """Return (x, y) centre of the node whose text contains label."""
    try:
        adb("shell", "uiautomator dump /sdcard/ui.xml >/dev/null 2>&1", timeout=30)
        xml = adb("shell", "cat /sdcard/ui.xml", timeout=30).stdout
    except subprocess.TimeoutExpired:
        return None
    for m in re.finditer(r'text="([^"]*)"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        if label in m.group(1):
            x = (int(m.group(2)) + int(m.group(4))) // 2
            y = (int(m.group(3)) + int(m.group(5))) // 2
            return x, y
    return None


def main():
    print("starting pm install…")
    proc = subprocess.Popen(
        [ADB, "-s", SERIAL, "shell", "pm install -r -d " + APK],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    deadline = time.time() + 120
    taps = 0
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        f = focus()
        if "packageinstaller" in f:
            spot = button_bounds("继续安装") or button_bounds("安装") or (620, 1755)
            print("prompt up, tapping %s" % (spot,))
            adb("shell", "input tap %d %d" % spot)
            taps += 1
            time.sleep(2.0)
        else:
            time.sleep(0.4)

    try:
        out = proc.communicate(timeout=60)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        out = "(timeout)"
    print("=== pm install output ===")
    print((out or "").strip())
    print("taps:", taps)

    info = adb("shell", "dumpsys package com.ghostlock.boot | grep -E 'lastUpdateTime|versionName' | head -2").stdout
    print("=== package ===")
    print(info.strip())


if __name__ == "__main__":
    main()
