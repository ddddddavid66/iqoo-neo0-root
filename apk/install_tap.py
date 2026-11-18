#!/usr/bin/env python3
"""Install the APK by tapping vivo's intercept prompt until the install lands.

vivo shows `com.android.packageinstaller.PackageInterceptActivity` ("外部来源应用" +
继续安装) for every adb install, and it re-shows it if the first tap races with the
activity being laid out. Detection through `dumpsys window | grep mCurrentFocus`
proves unreliable here (focus reads as null while the activity is up), so this
taps the button area on a fixed cadence and simply keeps going until the package
manager reports a new lastUpdateTime.
"""
import re
import subprocess
import sys
import time

ADB = r"D:\David\study2222\tool\platform-tools\adb.exe"
SERIAL = "10CE5P1A4G001PA"
APK = "/data/local/tmp/gl.apk"
TAP = (620, 1755)


def adb(*args, timeout=40):
    return subprocess.run([ADB, "-s", SERIAL, *args],
                          capture_output=True, text=True, timeout=timeout)


def intercept_up():
    out = adb("shell", "dumpsys activity activities 2>/dev/null | grep -c PackageInterceptActivity").stdout
    try:
        return int(out.strip()) > 0
    except ValueError:
        return False


def installed_version():
    out = adb("shell", "dumpsys package com.ghostlock.boot | grep -E 'versionCode|lastUpdateTime' | head -2").stdout
    return out.strip()


def main():
    before = installed_version()
    print("before:", before.replace("\n", " | ") or "(not installed)")

    proc = subprocess.Popen(
        [ADB, "-s", SERIAL, "shell", "pm install -r -d " + APK],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    deadline = time.time() + 90
    taps = 0
    while time.time() < deadline:
        # Do NOT break on proc.poll(): `pm install` returns INSTALL_FAILED_ABORTED
        # immediately, while vivo's intercept activity shows up a second or two
        # later and the install only really proceeds once it is confirmed.
        if intercept_up():
            adb("shell", "input tap %d %d" % TAP)
            taps += 1
        time.sleep(1.2)

    try:
        out = proc.communicate(timeout=60)[0]
    except subprocess.TimeoutExpired:
        proc.kill()
        out = "(install never returned)"

    print("=== pm install ===")
    print((out or "").strip())
    print("taps:", taps)

    after = installed_version()
    print("after :", after.replace("\n", " | ") or "(not installed)")
    if "Success" in (out or "") or after != before:
        print("RESULT: installed")
        return 0
    print("RESULT: still not installed")
    return 1


if __name__ == "__main__":
    sys.exit(main())
