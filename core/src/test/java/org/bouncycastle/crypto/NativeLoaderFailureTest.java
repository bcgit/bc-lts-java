package org.bouncycastle.crypto;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import junit.framework.TestCase;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;

/**
 * Failures in loading the native layer, and bad values of the properties read while it loads,
 * must leave the library usable in java, with a status that says what went wrong.
 * <p>
 * The loader runs once for each JVM, from class initialisation, so each case runs in a child JVM
 * started with the setting under test. The child reports the native status and then checks that
 * AES and the default SecureRandom still work; see {@link Child}.
 * </p>
 */
public class NativeLoaderFailureTest
    extends TestCase
{
    private static final String OK = "CHILD-OK";

    /**
     * A malformed org.bouncycastle.native.rand used to fail class initialisation, which left
     * CryptoServicesRegistrar unusable for the life of the JVM.
     */
    public void testBadRandSourceFallsBack()
        throws Exception
    {
        Result r = runChild(null, "-Dorg.bouncycastle.native.rand=BOGUS");
        r.assertOk();
        r.assertOutputContains("org.bouncycastle.native.rand");
        r.assertOutputContains("RAND=AUTO");
    }

    public void testBadRandRetriesFallsBack()
        throws Exception
    {
        Result r = runChild(null, "-Dorg.bouncycastle.native.rand.max_retries=many");
        r.assertOk();
        r.assertOutputContains("org.bouncycastle.native.rand.max_retries");
        r.assertOutputContains("RETRIES=1000");

        r = runChild(null, "-Dorg.bouncycastle.native.rand.max_retries=-1");
        r.assertOk();
        r.assertOutputContains("RETRIES=1000");
    }

    /**
     * A malformed cleanup delay used to fail the initialisation of DisposalDaemon, after which no
     * native object could be created.
     */
    public void testBadCleanupDelayFallsBack()
        throws Exception
    {
        String[] values = {"abc", "10s", "ms", "9223372036854775807"};
        for (int i = 0; i != values.length; i++)
        {
            Result r = runChild(null, "-Dorg.bouncycastle.native.cleanup_delay=" + values[i]);
            r.assertOk();
            if (r.nativeReady())
            {
                r.assertOutputContains("org.bouncycastle.native.cleanup_delay");
            }
        }
    }

    /**
     * An unknown forced variant is refused with a message saying so, not reported as
     * UNSUPPORTED.
     */
    public void testUnknownForcedVariantRefused()
        throws Exception
    {
        Result r = runChild(null, "-Dorg.bouncycastle.native.cpu_variant=bogus");
        r.assertOk();
        if (!r.status().equals("UNSUPPORTED"))
        {
            r.assertStatusContains("unknown native variant 'bogus'");
        }
    }

    /**
     * A forced variant needing CPU features the host lacks is refused. Loading it ended the JVM
     * with SIGILL at the first AES call.
     */
    public void testForcedVariantAboveHostRefused()
        throws Exception
    {
        Result best = runChild(null);
        best.assertOk();
        if (!best.nativeReady())
        {
            System.out.println("Skipping forced variant test: native not available: " + best.status());
            return;
        }

        String[] variants = {"avx", "vaes", "vaesf"};
        String bestVariant = best.value("VARIANT");
        int rank = java.util.Arrays.asList(variants).indexOf(bestVariant);
        if (rank < 0 || rank == variants.length - 1)
        {
            System.out.println("Skipping forced variant test: no variant above " + bestVariant);
            return;
        }

        for (int i = rank + 1; i < variants.length; i++)
        {
            Result r = runChild(null, "-Dorg.bouncycastle.native.cpu_variant=" + variants[i]);
            r.assertOk();
            r.assertStatusContains("forces native variant '" + variants[i] + "'");
            r.assertStatusContains("best variant it supports is '" + bestVariant + "'");
        }

        // a variant at or below the best one is still honoured.
        for (int i = 0; i <= rank; i++)
        {
            Result r = runChild(null, "-Dorg.bouncycastle.native.cpu_variant=" + variants[i]);
            r.assertOk();
            assertEquals("READY", r.status());
            assertEquals(variants[i], r.value("VARIANT"));
        }
    }

    /**
     * A probe library that will not load, here one that is not a shared object at all, reports
     * why and leaves java in use.
     */
    public void testUnloadableLibraryFallsBack()
        throws Exception
    {
        String probePath = probeResourcePath();
        if (probePath == null || NativeLoaderFailureTest.class.getResource(probePath) == null)
        {
            System.out.println("Skipping unloadable library test: no probe library for this platform");
            return;
        }

        File shadow = Files.createTempDirectory("bc-lts-shadow").toFile();
        try
        {
            File corrupt = new File(shadow, probePath.substring(1));
            corrupt.getParentFile().mkdirs();
            FileOutputStream out = new FileOutputStream(corrupt);
            out.write(Strings.toByteArray("this is not a shared object"));
            out.close();

            Result r = runChild(shadow.getAbsolutePath());
            r.assertOk();
            r.assertStatusContains("failed to load");
            assertFalse(r.nativeReady());
        }
        finally
        {
            deleteTree(shadow);
        }
    }

    /**
     * The directory the native libraries are installed in is private to its owner, whatever the
     * umask, so nobody else can replace a library between its installation and its loading.
     */
    public void testInstallDirectoryIsPrivate()
        throws Exception
    {
        File tmp = Files.createTempDirectory("bc-lts-tmp").toFile();
        try
        {
            Result r = runChild(null, "-Djava.io.tmpdir=" + tmp.getAbsolutePath(), "-D" + Child.LIST_TMP + "=true");
            r.assertOk();
            if (!r.nativeReady())
            {
                System.out.println("Skipping install directory test: native not available: " + r.status());
                return;
            }
            String perms = r.value("INSTALL_DIR_PERMS");
            if (!"n/a".equals(perms))
            {
                assertEquals("rwx------", perms);
            }
        }
        finally
        {
            deleteTree(tmp);
        }
    }

    /**
     * The child JVM: prints the native status, then shows that AES and the default SecureRandom
     * still work.
     */
    public static class Child
    {
        static final String LIST_TMP = "test.bclts.list_tmp";

        public static void main(String[] args)
            throws Exception
        {
            NativeServices services = CryptoServicesRegistrar.getNativeServices();
            System.out.println("STATUS=" + services.getStatusMessage());
            System.out.println("VARIANT=" + services.getVariant());
            System.out.println("RAND=" + services.getNativeRandSource());
            System.out.println("RETRIES=" + services.getMaxRNGRetries());

            if (Boolean.getBoolean(LIST_TMP))
            {
                String perms = "n/a";
                File[] dirs = new File(System.getProperty("java.io.tmpdir")).listFiles();
                for (int i = 0; dirs != null && i != dirs.length; i++)
                {
                    if (dirs[i].getName().startsWith("bc-lts-jni"))
                    {
                        try
                        {
                            perms = PosixFilePermissions.toString(Files.getPosixFilePermissions(dirs[i].toPath()));
                        }
                        catch (UnsupportedOperationException e)
                        {
                            // not a POSIX file system.
                        }
                    }
                }
                System.out.println("INSTALL_DIR_PERMS=" + perms);
            }

            // FIPS-197 appendix C.1
            BlockCipher aes = AESEngine.newInstance();
            aes.init(true, new KeyParameter(Hex.decode("000102030405060708090a0b0c0d0e0f")));
            byte[] out = new byte[16];
            aes.processBlock(Hex.decode("00112233445566778899aabbccddeeff"), 0, out, 0);
            if (!Arrays.areEqual(Hex.decode("69c4e0d86a7b0430d8cdb78070b4c55a"), out))
            {
                throw new IllegalStateException("AES gave the wrong answer: " + Hex.toHexString(out));
            }

            byte[] random = new byte[32];
            CryptoServicesRegistrar.getSecureRandom().nextBytes(random);

            System.out.println(OK);
        }
    }

    private static String probeResourcePath()
    {
        String os = Strings.toLowerCase(System.getProperty("os.name", ""));
        String arch = Strings.toLowerCase(System.getProperty("os.arch", ""));
        String platform = os.contains("linux") ? "linux" : (os.contains("mac") || os.contains("darwin")) ? "darwin" : null;
        if (platform == null)
        {
            return null;
        }
        if (arch.contains("aarch64"))
        {
            return "/native/" + platform + "/arm64/probe/" + System.mapLibraryName("bc-probe-le");
        }
        if (arch.contains("amd64") || arch.contains("x86_64"))
        {
            return "/native/" + platform + "/x86_64/probe/" + System.mapLibraryName("bc-probe");
        }
        return null;
    }

    private static Result runChild(String classPathPrefix, String... jvmArgs)
        throws Exception
    {
        String classPath = System.getProperty("java.class.path");
        if (classPathPrefix != null)
        {
            classPath = classPathPrefix + File.pathSeparator + classPath;
        }

        List<String> cmd = new ArrayList<String>();
        cmd.add(System.getProperty("java.home") + File.separator + "bin" + File.separator + "java");
        cmd.add("-cp");
        cmd.add(classPath);
        for (int i = 0; i != jvmArgs.length; i++)
        {
            cmd.add(jvmArgs[i]);
        }
        cmd.add(Child.class.getName());

        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        String output = readAll(p.getInputStream());
        if (!p.waitFor(120, TimeUnit.SECONDS))
        {
            p.destroyForcibly();
            fail("child JVM did not finish: " + cmd + "\n" + output);
        }
        return new Result(cmd, p.exitValue(), output);
    }

    private static String readAll(InputStream in)
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) >= 0)
        {
            bOut.write(buf, 0, n);
        }
        return Strings.fromByteArray(bOut.toByteArray());
    }

    private static void deleteTree(File f)
    {
        File[] children = f.listFiles();
        for (int i = 0; children != null && i != children.length; i++)
        {
            deleteTree(children[i]);
        }
        f.delete();
    }

    private static class Result
    {
        private final List<String> cmd;
        private final int exit;
        private final String output;

        Result(List<String> cmd, int exit, String output)
        {
            this.cmd = cmd;
            this.exit = exit;
            this.output = output;
        }

        void assertOk()
        {
            assertTrue("child failed, exit " + exit + ": " + cmd + "\n" + output, exit == 0 && output.contains(OK));
        }

        void assertOutputContains(String s)
        {
            assertTrue("expected \"" + s + "\" in child output: " + cmd + "\n" + output, output.contains(s));
        }

        void assertStatusContains(String s)
        {
            assertTrue("expected \"" + s + "\" in status: " + cmd + "\n" + output, status().contains(s));
        }

        boolean nativeReady()
        {
            return "READY".equals(status());
        }

        String status()
        {
            return value("STATUS");
        }

        String value(String key)
        {
            String[] lines = output.split("\\r?\\n");
            for (int i = 0; i != lines.length; i++)
            {
                if (lines[i].startsWith(key + "="))
                {
                    return lines[i].substring(key.length() + 1);
                }
            }
            fail("no " + key + " in child output: " + cmd + "\n" + output);
            return null;
        }
    }
}
