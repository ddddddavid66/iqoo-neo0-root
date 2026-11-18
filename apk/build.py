#!/usr/bin/env python3
"""Build the GhostLock boot APK with the SDK that already sits in tool/.

No Gradle: aapt2 + javac + d8 + zipalign + apksigner is the whole pipeline and
it keeps the build reproducible with just a JDK and build-tools.

Two things about this APK are load-bearing and easy to break:

  * ``android:extractNativeLibs="true"`` — the payload must end up unpacked in
    nativeLibraryDir, because that is the only place an app is allowed to exec.
  * ``targetSdkVersion 28`` — keeps the app in the untrusted_app_27 SELinux
    domain, which has a noticeably wider surface than untrusted_app. The exploit
    needs every bit of it.

Usage:
    python build.py                # full build
    python build.py --fetch-ksud   # pull libksud.so off the phone first
"""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOOL = Path(r"D:\David\study2222\tool")
SDK = TOOL / "android-sdk"
BT = SDK / "build-tools" / "37.0.0"
PLATFORM_JAR = SDK / "platforms" / "android-36" / "android.jar"
JDK = TOOL / "jdk" / "jdk-21.0.12.1+1"

BUILD = ROOT / "build"
OUT_APK = BUILD / "ghostlock-boot-unsigned.apk"
ALIGNED = BUILD / "ghostlock-boot-aligned.apk"
SIGNED = BUILD / "ghostlock-boot.apk"
KEYSTORE = ROOT / "keystore.jks"
KS_KEY_ALIAS = "ghostlock"
KS_PASS = "ghostlock"
ADB = TOOL / "platform-tools" / "adb.exe"
SERIAL = "10CE5P1A4G001PA"

MIN_SDK = "28"
TARGET_SDK = "28"


def run(cmd: list[str], **kw) -> None:
    print("  $", " ".join(str(c) for c in cmd))
    proc = subprocess.run([str(c) for c in cmd], **kw)
    if proc.returncode != 0:
        sys.exit("FAILED: %s" % " ".join(str(c) for c in cmd))


def need(path: Path, what: str) -> None:
    if not path.exists():
        sys.exit("missing %s: %s" % (what, path))


def fetch_ksud() -> None:
    """Pull ksud off the device.

    Two sources, in order:
      1. /data/adb/ksud — what KernelSU itself deploys. Root-only, and always
         matches the installed manager version.
      2. The largest .so under an app lib dir — SukiSU renames it
         (libdhxddxovny.so here), so it is found by size rather than by name.

    Wildcards do not expand through `adb shell` for other apps' directories, and
    /data/adb is root-only, so both paths go through `su -c`.
    """
    dst = ROOT / "lib" / "arm64-v8a" / "libksud.so"
    if dst.is_file() and dst.stat().st_size > 1_000_000:
        print("  ksud already staged:", dst.name, dst.stat().st_size, "bytes")
        return
    need(ADB, "adb")
    dst.parent.mkdir(parents=True, exist_ok=True)
    stage = "/data/local/tmp/ksud.pull"

    probe = subprocess.run(
        [str(ADB), "-s", SERIAL, "shell", "su -c 'ls -l /data/adb/ksud'"],
        capture_output=True, text=True)
    if "ksud" in probe.stdout and "No such" not in probe.stdout:
        print("  source: /data/adb/ksud")
        run([str(ADB), "-s", SERIAL, "shell",
             "su -c 'cp /data/adb/ksud %s && chmod 644 %s'" % (stage, stage)])
    else:
        print("  source: scanning app lib dirs (root)")
        discovery = ROOT / "build" / "find-ksud.sh"
        discovery.parent.mkdir(parents=True, exist_ok=True)
        discovery.write_text(
            "#!/system/bin/sh\n"
            "best=\n"
            "bestsz=0\n"
            "for d in /data/app/*/*/lib/arm64; do\n"
            "  for f in \"$d\"/*.so; do\n"
            "    [ -f \"$f\" ] || continue\n"
            "    sz=$(stat -c %s \"$f\" 2>/dev/null || echo 0)\n"
            "    if [ \"$sz\" -gt \"$bestsz\" ]; then bestsz=$sz; best=$f; fi\n"
            "  done\n"
            "done\n"
            "if [ -n \"$best\" ]; then cp \"$best\" " + stage + "; chmod 644 " + stage + "; "
            "echo \"picked $best ($bestsz)\"; fi\n",
            encoding="utf-8", newline="\n")
        remote = "/data/local/tmp/find-ksud.sh"
        run([str(ADB), "-s", SERIAL, "push", discovery, remote])
        res = subprocess.run(
            [str(ADB), "-s", SERIAL, "shell", "su -c 'sh " + remote + "'"],
            capture_output=True, text=True)
        if "picked" not in res.stdout:
            sys.exit("no ksud found on device:\n%s\n%s" % (res.stdout, res.stderr))
        print(" ", res.stdout.strip().splitlines()[-1])

    run([str(ADB), "-s", SERIAL, "pull", stage, dst.as_posix()])
    size = dst.stat().st_size
    if size < 1_000_000:
        sys.exit("pulled ksud looks wrong: %d bytes" % size)
    print("  staged:", dst.name, size, "bytes")


def clean() -> None:
    if BUILD.exists():
        shutil.rmtree(BUILD)
    BUILD.mkdir(parents=True)


def compile_resources() -> Path:
    res_zip = BUILD / "res.zip"
    run([BT / "aapt2.exe", "compile", "--dir", ROOT / "res", "-o", res_zip])
    return res_zip


def link_base(res_zip: Path) -> None:
    gen = BUILD / "gen"
    gen.mkdir(parents=True, exist_ok=True)
    run([
        BT / "aapt2.exe", "link",
        "-o", OUT_APK,
        "-I", PLATFORM_JAR,
        "--manifest", ROOT / "AndroidManifest.xml",
        "-R", res_zip,
        "--java", gen,
        "-A", ROOT / "assets",
        "--min-sdk-version", MIN_SDK,
        "--target-sdk-version", TARGET_SDK,
        "--auto-add-overlay",
    ])


def compile_java() -> list[Path]:
    classes = BUILD / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    sources = sorted(str(p) for p in (ROOT / "src").rglob("*.java"))
    sources += sorted(str(p) for p in (BUILD / "gen").rglob("*.java"))
    if not sources:
        sys.exit("no java sources")
    run([
        JDK / "bin" / "javac.exe",
        "-source", "8", "-target", "8",
        "-bootclasspath", PLATFORM_JAR,
        "-encoding", "UTF-8",
        "-nowarn",
        "-d", classes,
        *sources,
    ])
    return sorted(classes.rglob("*.class"))


def dex(class_files: list[Path]) -> Path:
    dexdir = BUILD / "dex"
    dexdir.mkdir(parents=True, exist_ok=True)
    run([
        BT / "d8.bat",
        "--lib", PLATFORM_JAR,
        "--min-api", MIN_SDK,
        "--output", dexdir,
        *class_files,
    ])
    out = dexdir / "classes.dex"
    if not out.is_file():
        sys.exit("d8 produced no classes.dex")
    return out


def assemble(dex_file: Path) -> None:
    """Append classes.dex and the native libraries to the aapt2-built APK."""
    payload_lib = ROOT / "lib" / "arm64-v8a"
    libs = sorted(payload_lib.glob("*.so"))
    if not libs:
        sys.exit("no native libraries staged")

    tmp = BUILD / "assemble.apk"
    with zipfile.ZipFile(OUT_APK, "r") as src, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as dst:
        for item in src.infolist():
            dst.writestr(item, src.read(item.filename))
        dst.write(dex_file, "classes.dex")
        for lib in libs:
            arc = "lib/arm64-v8a/%s" % lib.name
            # Stored, not deflated: the loader maps these straight out of the
            # APK during install and deflated entries only slow that down.
            info = zipfile.ZipInfo(arc)
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o644 << 16
            dst.writestr(info, lib.read_bytes())

    shutil.move(str(tmp), str(OUT_APK))
    print("  assembled:", OUT_APK, OUT_APK.stat().st_size, "bytes")


def align() -> None:
    run([BT / "zipalign.exe", "-p", "-f", "4", OUT_APK, ALIGNED])


def ensure_keystore() -> None:
    if KEYSTORE.is_file():
        return
    print("  generating keystore…")
    run([
        JDK / "bin" / "keytool.exe",
        "-genkeypair",
        "-keystore", KEYSTORE,
        "-alias", KS_KEY_ALIAS,
        "-keyalg", "RSA",
        "-keysize", "2048",
        "-validity", "10000",
        "-storepass", KS_PASS,
        "-keypass", KS_PASS,
        "-dname", "CN=GhostLock Boot, OU=local, O=local, L=local, S=local, C=CN",
    ])


def sign() -> None:
    ensure_keystore()
    # build-tools 37 signs with v3 only unless told otherwise. v3 alone verifies,
    # but some system components still insist on v2 for side-loaded APKs, so ask
    # for both explicitly. v1 stays off: minSdk 28 means nothing reads it.
    run([
        BT / "apksigner.bat", "sign",
        "--ks", KEYSTORE,
        "--ks-key-alias", KS_KEY_ALIAS,
        "--ks-pass", "pass:" + KS_PASS,
        "--key-pass", "pass:" + KS_PASS,
        "--min-sdk-version", MIN_SDK,
        "--v1-signing-enabled", "false",
        "--v2-signing-enabled", "true",
        "--v3-signing-enabled", "true",
        "--out", SIGNED,
        ALIGNED,
    ])
    run([BT / "apksigner.bat", "verify", "--verbose", SIGNED])


def report() -> None:
    print()
    print("APK :", SIGNED)
    print("size:", SIGNED.stat().st_size, "bytes")
    with zipfile.ZipFile(SIGNED) as z:
        names = z.namelist()
        for want in ("classes.dex", "AndroidManifest.xml", "resources.arsc",
                     "assets/profile.bin", "assets/vrpatch.ko",
                     "lib/arm64-v8a/libghostlock.so", "lib/arm64-v8a/libksud.so"):
            print("  %-36s %s" % (want, "OK" if want in names else "MISSING"))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fetch-ksud", action="store_true",
                    help="pull libksud.so off the device before building")
    ap.add_argument("--no-clean", action="store_true")
    args = ap.parse_args()

    for path, what in ((BT / "aapt2.exe", "aapt2"), (PLATFORM_JAR, "android.jar"),
                       (JDK / "bin" / "javac.exe", "javac"), (BT / "d8.bat", "d8")):
        need(path, what)

    if args.fetch_ksud:
        fetch_ksud()

    ksud = ROOT / "lib" / "arm64-v8a" / "libksud.so"
    payload = ROOT / "lib" / "arm64-v8a" / "libghostlock.so"
    need(payload, "libghostlock.so")
    if not ksud.is_file():
        print("WARNING: libksud.so is missing — the APK will build, but the")
        print("         late-load cannot run without it. Run: python build.py --fetch-ksud")
    os.chdir(ROOT)

    print("[1/6] resources")
    if not args.no_clean:
        clean()
    res_zip = compile_resources()

    print("[2/6] link")
    link_base(res_zip)

    print("[3/6] javac")
    classes = compile_java()

    print("[4/6] d8")
    dex_file = dex(classes)

    print("[5/6] assemble + align")
    assemble(dex_file)
    align()

    print("[6/6] sign")
    sign()
    report()


if __name__ == "__main__":
    main()
