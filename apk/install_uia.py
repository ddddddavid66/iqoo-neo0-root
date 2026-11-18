#!/usr/bin/env python3
"""Install the APK by locating vivo's 继续安装 button through uiautomator.

Hard-coded coordinates are not trustworthy: the intercept page shifts with the
status bar and the notch, and a tap that lands outside the button simply
dismisses the page without installing anything (which is what a fixed (620,1755)
did — the activity closed, the package never appeared).

`pm install` also returns INSTALL_FAILED_ABORTED right away, long before the
prompt appears, so the tap loop is driven purely by whether the intercept
activity is on screen.
"""
import re
import subprocess
import sys
import time

ADB = r"D:\David\study2222\tool\platform-tools\adb.exe"
SERIAL = "10CE5P1A4G001PA"
APK = "/data/local/tmp/gl.apk"

LABELS = ("继续安装", "安装", "继续", "OK", "确定")


def adb(*args, timeout=40):
    return subprocess.run([ADB, "-s", SERIAL, *args],
                          capture_output=True, text=True, timeout=timeout)


def intercept_up():
    out = adb("shell", "dumpsys activity activities 2>/dev/null | grep -c PackageInterceptActivity").stdout
    try:
        return int(out.strip()) > 0
    except ValueError:
        return False


def find_button():
    """Dump the current UI and return the centre of the most likely button."""
    try:
        adb("shell", "rm -f /sdcard/ui.xml")
        adb("shell", "uiautomator dump /sdcard/ui.xml", timeout=45)
        xml = adb("shell", "cat /sdcard/ui.xml", timeout=45).stdout
    except subprocess.TimeoutExpired:
        return None
    if not xml or "<hierarchy" not in xml:
        return None
    found = {}
    for m in re.finditer(
            r'text="([^"]*)"[^>]*?bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"', xml):
        text = m.group(1)
        for label in LABELS:
            if label in text:
                x = (int(m.group(2)) + int(m.group(4))) // 2
                y = (int(m.group(3)) + int(m.group(5))) // 2
                found[label] = (x, y, text)
    for label in LABELS:
        if label in found:
            return found[label]
    return None


def version():
    return adb("shell", "dumpsys package com.ghostlock.boot | grep -E 'versionCode|lastUpdateTime' | head -2").stdout.strip()


def main():
    before = version()
    print("before:", before.replace("\n", " | ") or "(not installed)")

    subprocess.Popen([ADB, "-s", SERIAL, "shell", "pm install -r -d " + APK],
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    deadline = time.time() + 150
    taps = 0
    while time.time() < deadline:
        if not intercept_up():
            time.sleep(1.0)
            continue
        time.sleep(1.5)  # let the activity finish laying out
        spot = find_button()
        if spot:
            x, y, text = spot
            print("tap '%s' at (%d,%d)" % (text, x, y))
            adb("shell", "input tap %d %d" % (x, y))
            taps += 1
            time.sleep(4)
        else:
            print("prompt up but no button found in dump; tapping centre")
            adb("shell", "input tap 620 1755")
            taps += 1
            time.sleep(4)
        after = version()
        if after and after != before:
            print("=== installed ===")
            print(after)
            return 0

    print("taps:", taps)
    after = version()
    print("after :", after.replace("\n", " | ") or "(not installed)")
    return 0 if after and after != before else 1


if __name__ == "__main__":
    sys.exit(main())
