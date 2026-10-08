package org.bouncycastle.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.jar.JarException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.Streams;

class NativeLoader
{

    private static final Logger LOG = Logger.getLogger(NativeLoader.class.getName());

    public static final String BCLTS_LIB_CPU_VARIANT = "org.bouncycastle.native.cpu_variant";


    private static boolean nativeLibsAvailableForSystem = false;
    private static boolean nativeInstalled = false;
    private static boolean nativeEnabled = true;
    private static String nativeStatusMessage = "Driver load not attempted";

    // true once the loader finds the platform in scope, so that a later failure is a failure to
    // load, reported in detail, rather than a platform the native layer does not support.
    private static boolean platformInScope = false;

    // the variants a forced variant may name, weakest first: a host that supports one supports
    // every variant before it.
    private static final String[] X86_64_VARIANTS = {"avx", "vaes", "vaesf"};
    private static final String[] ARM64_VARIANTS = {"neon-le"};

    private static String selectedVariant = null;

    private static boolean javaSupportOnly = true;

    private static final NativeServices nativeServices = new DefaultNativeServices();

    private static AtomicBoolean loadAttempted = new AtomicBoolean(false);

    static
    {
        loadDriver();
    }

    static synchronized boolean isJavaSupportOnly()
    {
        return javaSupportOnly;
    }

    /**
     * Native has been installed.
     *
     * @return true if the native lib has been installed.
     */
    static synchronized boolean isNativeInstalled()
    {
        return nativeInstalled;
    }

    /**
     * Native is available.
     *
     * @return true if native libs have been installed and are NOT disabled.
     */
    static synchronized boolean isNativeAvailable()
    {
        return nativeLibsAvailableForSystem && nativeInstalled && nativeEnabled;
    }

    /**
     * Disable native library even if loaded.
     *
     * @param enabled when false will disable the use of native extensions.
     */
    static synchronized void setNativeEnabled(boolean enabled)
    {
        nativeEnabled = enabled;
    }

    static synchronized String getNativeStatusMessage()
    {
        return nativeStatusMessage;
    }

    /**
     * Return true if the platform is one the native layer supports, but loading the native
     * libraries failed.
     */
    static synchronized boolean isLoadFailure()
    {
        return platformInScope && !nativeInstalled;
    }

    static synchronized String getSelectedVariant()
    {
        return selectedVariant;
    }

    static String getFile(String path)
    {
        String value;
        try
        {
            InputStream in = NativeLoader.class.getResourceAsStream(path);
            value = Strings.fromByteArray(Streams.readAll(in));
            in.close();
        }
        catch (Exception ex)
        {
            return null;
        }
        return value;
    }

    static List<String> loadVariantsDeps(String depFile, String libName)
    {
        String data = getFile(depFile);
        if (data == null)
        {
            return Collections.emptyList();
        }
        ArrayList<String> out = new ArrayList<String>();
        for (String line : data.split("\n"))
        {
            line = line.trim();
            String[] parts = line.split(":");
            if (parts[0].trim().equals(libName))
            {
                out.add(parts[1].trim());
            }
        }
        return Collections.unmodifiableList(out);
    }


    static File installLib(String name, String libPathSegment, String jarPath, File bcLibPath,
                           Set<File> filesInInstallLocation)
            throws Exception
    {

        //
        // Copy nominated dep for library into bcLibPath
        //

        String libLocalName = System.mapLibraryName(name);

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine("attempting to install: " + libLocalName);
        }

        List<String> deps = loadVariantsDeps(jarPath + "/deps.list", libLocalName);
        for (String dep : deps)
        {
            filesInInstallLocation.remove(copyFromJar(jarPath + "/" + dep, bcLibPath, dep));
        }
        File libToLoad = copyFromJar(libPathSegment + "/" + libLocalName, bcLibPath, libLocalName);
        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine("installed " + libToLoad);
        }

        filesInInstallLocation.remove(libToLoad);


        return libToLoad;
    }

    static boolean isLE()
    {
        return ByteOrder.nativeOrder().equals(ByteOrder.LITTLE_ENDIAN);
    }

    static synchronized void loadDriver()
    {

        LOG.log(Level.FINE, "native loader start");

        if (loadAttempted.getAndSet(true))
        {
            LOG.log(Level.FINE, "native loader already attempted load");
            return;
        }

        //
        // This runs from class initialisation, so anything escaping it would leave the class, and
        // CryptoServicesRegistrar with it, unusable for the life of the JVM. A failure here means
        // only that the native layer is not used.
        //
        try
        {
            installAndLoad();
        }
        catch (LinkageError e)
        {
            loadFailed(e);
        }
        catch (RuntimeException e)
        {
            loadFailed(e);
        }
    }

    private static void loadFailed(Throwable e)
    {
        nativeLibsAvailableForSystem = false;
        nativeInstalled = false;
        javaSupportOnly = true;
        nativeStatusMessage = "native libraries failed to load, using java support only: " + e;
        LOG.warning(nativeStatusMessage);
    }

    /**
     * Return the variants a forced variant may name on the platform.
     */
    private static String[] knownVariants(boolean isARM)
    {
        return isARM ? ARM64_VARIANTS : X86_64_VARIANTS;
    }

    private static String join(String[] values)
    {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i != values.length; i++)
        {
            if (i != 0)
            {
                sb.append(", ");
            }
            sb.append(values[i]);
        }
        return sb.toString();
    }

    private static int variantRank(String[] variants, String variant)
    {
        for (int i = 0; i != variants.length; i++)
        {
            if (variants[i].equals(variant))
            {
                return i;
            }
        }
        return -1;
    }

    /**
     * Create the directory with access for its owner only, where the file system allows that.
     *
     * @return true if the directory was created, false if it already exists.
     */
    private static boolean makePrivateDir(File dir)
        throws IOException
    {
        try
        {
            Files.createDirectory(dir.toPath(),
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
            return true;
        }
        catch (FileAlreadyExistsException e)
        {
            return false;
        }
        catch (UnsupportedOperationException e)
        {
            // not a POSIX file system.
            if (!dir.mkdir())
            {
                if (dir.exists())
                {
                    return false;
                }
                throw new IOException("unable to create " + dir);
            }
            dir.setReadable(false, false);
            dir.setReadable(true, true);
            dir.setWritable(false, false);
            dir.setWritable(true, true);
            dir.setExecutable(false, false);
            dir.setExecutable(true, true);
            return true;
        }
    }

    private static void installAndLoad()
    {

        String forcedVariant = Properties.getPropertyValue(BCLTS_LIB_CPU_VARIANT);

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine("forced variant is: " + (forcedVariant != null ? forcedVariant : " not defined"));
        }

        // No variants defined at all, or a
        // single variant defined that is java only.
        //
        if ("java".equals(forcedVariant))
        {
            javaSupportOnly = true;
            nativeInstalled = false;
            nativeStatusMessage = "java support only";
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, "examining properties to determine platform and architecture");
        }

        String arch_ = Strings.toLowerCase(Properties.getPropertyValue("os.arch", ""));
        String os_ = Strings.toLowerCase(Properties.getPropertyValue("os.name", ""));
        String platform = null;
        String arch = null;
        boolean isARM = false;

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, "host ARCH: " + arch_);
            LOG.log(Level.FINE, "host OS: " + os_);
        }


        if (os_.contains("linux"))
        {
            platform = "linux";
        }
        else if (os_.contains("mac") || os_.contains("darwin"))
        {
            platform = "darwin";
        }


        if (platform == null)
        {
            nativeStatusMessage = "OS '" + os_ + "' is not supported.";
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        if ((arch_.contains("x86") || (arch_.contains("amd")) && arch_.contains("64")))
        {
            arch = "x86_64";
        }
        else if (arch_.contains("aarch64"))
        {
            arch = "arm64";
            isARM = true;
        }


        if (arch == null)
        {
            nativeStatusMessage = "architecture '" + arch_ + "' is not supported";
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, "derived native platform: " + platform);
            LOG.log(Level.FINE, "derived native architecture: " + arch);
        }

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, "begin determining path to install native libraries");
        }

        File bcLtsLibPath = AccessController.doPrivileged(new PrivilegedAction<File>()
        {
            @Override
            public File run()
            {

                File ioTmpDir = new File(Properties.getPropertyValue("java.io.tmpdir"));
                if (!ioTmpDir.exists())
                {
                    nativeInstalled = false;
                    nativeStatusMessage = ioTmpDir + " did not exist";
                    LOG.fine("exited with " + nativeStatusMessage);
                    return null;
                }


                try
                {

                    //
                    // Create a temporary file, we cannot use the inbuilt method as it will attempt to start
                    // an entropy source and the provider is not in a ready state.
                    //
                    //
                    // The directory is private to its owner, so nobody else can replace a library
                    // between its installation and its loading. Names that already exist are
                    // skipped; any other failure ends the attempt.
                    //
                    File dir = null;
                    long time = System.nanoTime();
                    for (int t = 0; t < 1000; t++)
                    {
                        dir = new File(ioTmpDir, "bc-lts-jni" + Long.toString(time + t, 32) + "-libs");
                        if (makePrivateDir(dir))
                        {
                            break;
                        }
                        dir = null;
                    }

                    if (dir == null)
                    {
                        nativeInstalled = false;
                        nativeStatusMessage = "unable to create directory in " + ioTmpDir + " after 1000 unique " +
                                "attempts";
                        LOG.fine("exited with " + nativeStatusMessage);
                        return null;
                    }

                    //
                    // Create a directory using that file as a stem
                    //
                    if (!dir.exists())
                    {
                        nativeInstalled = false;
                        nativeStatusMessage = "unable to create temp directory for jni libs: " + dir;
                        LOG.fine("exited with " + nativeStatusMessage);
                        return null;
                    }

                    final File tmpDir = dir;

                    //
                    // Shutdown hook clean up installed libraries.
                    //
                    Runtime.getRuntime().addShutdownHook(new Thread(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            if (LOG.isLoggable(Level.FINE))
                            {
                                LOG.fine("cleanup shutdown hook started");
                            }

                            if (!tmpDir.exists())
                            {
                                return;
                            }
                            boolean isDeleted = true;
                            File[] files = tmpDir.isDirectory() ? tmpDir.listFiles() : null;
                            if (files != null)
                            {
                                for (File f : files)
                                {
                                    isDeleted &= f.delete();
                                }
                            }

                            isDeleted &= tmpDir.delete();

                            if (!isDeleted)
                            {
                                LOG.fine(" failed to delete: " + tmpDir.getAbsolutePath());
                            }
                            else
                            {
                                LOG.fine("successfully cleaned up: " + tmpDir.getAbsolutePath());
                            }
                        }
                    }));

                    return tmpDir;
                }
                catch (Exception ex)
                {
                    nativeInstalled = false;
                    nativeStatusMessage = "failed because it was not able to create a temporary file in 'java.io" +
                            ".tmpdir' " + ex.getMessage();
                    LOG.fine("exited with " + nativeStatusMessage);
                    return null;
                }

            }
        });

        if (bcLtsLibPath == null)
        {
            return;
        }

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, "native library install location: " + bcLtsLibPath.getAbsolutePath());
        }


        //
        // We track all the existing files in the installation location.
        // During installation, we remove them from this set if they have been replaced.
        // if any files are remaining in the set then there were unaccounted for files in
        // the installation location, and we cannot start the module.
        //
        Set<File> filesInInstallLocation = new HashSet<File>();

        File[] existingFiles = bcLtsLibPath.listFiles();
        if (existingFiles == null)
        {
            nativeStatusMessage = "unable to list the native library install location " + bcLtsLibPath;
            nativeInstalled = false;
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        for (File f : existingFiles)
        {
            filesInInstallLocation.add(f);
        }

        if (LOG.isLoggable(Level.FINE))
        {
            if (!filesInInstallLocation.isEmpty())
            {
                for (File file : filesInInstallLocation)
                {
                    LOG.log(Level.FINE, "found in install location: " + file.getAbsolutePath());
                }
            }
        }

        //
        // Point to the directory in the jar where the native libs are located.
        //
        String jarDir = String.format("/native/%s/%s", platform, arch);


        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, "library path within LTS jar: " + jarDir);
        }


        //
        // Look for a probe library, it matches the platform and architecture.
        // It needs to exist regardless of any forced variant, if it does not exist
        // any forced variant is not going to function anyway.
        //
        String probeLibInJarPath = String.format("/native/%s/%s/probe", platform, arch);

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, "begin install probe library from: " + probeLibInJarPath);
        }

        String probeLibPrefix;
        if (isARM)
        {
            if (isLE())
            {
                probeLibPrefix = "bc-probe-le";
            }
            else
            {
                nativeStatusMessage = String.format("ARM big-endian is not supported", platform,
                        arch);
                nativeInstalled = false;
                LOG.fine("exited with " + nativeStatusMessage);
                return;
            }
        }
        else
        {
            probeLibPrefix = "bc-probe";
        }


        InputStream tmpIn = NativeLoader.class.getResourceAsStream(probeLibInJarPath + "/" + System.mapLibraryName(
                probeLibPrefix));
        if (tmpIn == null)
        {
            nativeStatusMessage = String.format("platform '%s' and architecture '%s' are not supported", platform,
                    arch);
            nativeInstalled = false;
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }
        try
        {
            tmpIn.close();
        }
        catch (IOException ignored)
        {
        }

        platformInScope = true;

        //
        // Endeavour ot install the probe library, if this does not install then
        // forced variants will be usable.
        //
        try
        {
            // Install probe lib
            final File lib = installLib(probeLibPrefix, probeLibInJarPath, jarDir, bcLtsLibPath,
                    filesInInstallLocation);

            AccessController.doPrivileged(
                    new PrivilegedAction<Object>()
                    {
                        @Override
                        public Object run()
                        {
                            System.load(lib.getAbsolutePath());
                            return new Object();
                        }
                    }
            );


        }
        catch (Throwable ex)
        {
            // Throwable, as System.load reports its failures with UnsatisfiedLinkError.
            nativeStatusMessage = "probe lib failed to load " + ex.getMessage();
            nativeInstalled = false;
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        try
        {
            selectedVariant = VariantSelector.getBestVariantName();
        }
        catch (Throwable ex)
        {
            nativeStatusMessage = "probe lib failed return a variant " + ex.getMessage();
            nativeInstalled = false;
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        if ("none".equals(selectedVariant))
        {
            platformInScope = false;
            javaSupportOnly = true;
            nativeInstalled = false;
            nativeStatusMessage = "probe returned no suitable CPU features, java support only";
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        if (forcedVariant != null)
        {
            //
            // A forced variant must be one this host can run: loading one that needs CPU features
            // the host does not have ends the JVM at the first instruction it cannot execute.
            //
            String[] variants = knownVariants(isARM);
            int forcedRank = variantRank(variants, forcedVariant);
            if (forcedRank < 0)
            {
                nativeStatusMessage = String.format("%s names an unknown native variant '%s', expected one of %s " +
                    "or java", BCLTS_LIB_CPU_VARIANT, forcedVariant, join(variants));
                nativeInstalled = false;
                LOG.warning(nativeStatusMessage);
                return;
            }
            if (forcedRank > variantRank(variants, selectedVariant))
            {
                nativeStatusMessage = String.format("%s forces native variant '%s', which needs CPU features this " +
                    "host does not have; the best variant it supports is '%s'", BCLTS_LIB_CPU_VARIANT, forcedVariant,
                    selectedVariant);
                nativeInstalled = false;
                LOG.warning(nativeStatusMessage);
                return;
            }

            selectedVariant = forcedVariant;
        }

        String variantPathInJar = String.format("/native/%s/%s/%s", platform, arch, selectedVariant);//  variantPaths
        // .get(selectedVariant);

        try
        {
            //
            // Derive the suffix it is the last part of the variant name
            // eg: linux-x86_64-sse has a suffix of "sse"
            //


            final File lib = installLib("bc-lts-" + selectedVariant, variantPathInJar, jarDir, bcLtsLibPath,
                    filesInInstallLocation);


            //
            // If not empty we have unexpected files in the library path
            //
            if (!filesInInstallLocation.isEmpty())
            {
                StringBuilder sBld = new StringBuilder();
                for (File f : filesInInstallLocation)
                {
                    if (sBld.length() != 0)
                    {
                        sBld.append(",");
                    }
                    sBld.append(f.getName());
                }
                nativeStatusMessage = String.format("unexpected files in %s: %s", bcLtsLibPath.toString(),
                        sBld.toString());
                nativeInstalled = false;
                LOG.fine("exited with " + nativeStatusMessage);
                return;
            }

            AccessController.doPrivileged(
                    new PrivilegedAction<Object>()
                    {
                        @Override
                        public Object run()
                        {
                            System.load(lib.getAbsolutePath());
                            return new Object();
                        }
                    }
            );

        }
        catch (Throwable ex)
        {
            // Throwable, as System.load reports its failures with UnsatisfiedLinkError.
            nativeStatusMessage = "native capabilities lib failed to load " + ex.getMessage();
            nativeInstalled = false;
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }


        if (!selectedVariant.equals(NativeLibIdentity.getLibraryIdent()))
        {
            nativeStatusMessage = String.format("loaded native library variant is %s but the requested library " +
                    "variant is %s", NativeLibIdentity.getLibraryIdent(), selectedVariant);
            nativeInstalled = false;
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        nativeLibsAvailableForSystem = true;
        nativeStatusMessage = "successfully loaded";
        nativeInstalled = true;
        javaSupportOnly = false;

        if (LOG.isLoggable(Level.FINE))
        {
            LOG.log(Level.FINE, nativeStatusMessage);
            LOG.fine("native loader has finished");
        }
    }

    public static boolean isNativeLibsAvailableForSystem()
    {
        return nativeLibsAvailableForSystem;
    }

    static NativeServices getNativeServices()
    {
        return nativeServices;
    }

    static boolean hasNativeService(String feature)
    {
        return isNativeAvailable() && nativeServices.hasService(feature);
    }

    private static byte[] takeSHA256Digest(InputStream in)
    {
        try
        {
            byte[] buf = new byte[65535];
            SHA256Digest dig = new SHA256Digest();
            int len;
            while ((len = in.read(buf)) >= 0)
            {
                dig.update(buf, 0, len);
            }
            byte[] res = new byte[dig.getDigestSize()];
            dig.doFinal(res, 0);
            return res;
        }
        catch (IOException ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }
    }

    private static File copyFromJar(String inJarPath, File dir, String targetName)
            throws Exception
    {
        InputStream inputStream = NativeLoader.class.getResourceAsStream(inJarPath);
        if (inputStream == null)
        {
            throw new JarException(inJarPath + " lib not found in jar");
        }
        File dest = new File(dir, targetName);

        if (dest.exists())
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("installation target exists: " + dest.getAbsolutePath());
            }

            FileInputStream fin = new FileInputStream(dest);
            byte[] currentDigest = takeSHA256Digest(fin);
            fin.close();

            if (LOG.isLoggable(Level.FINE))
            {
                // -DM Hex.toHexString
                LOG.fine("existing file digest: " + Hex.toHexString(currentDigest));
            }

            byte[] newDigest = takeSHA256Digest(inputStream);
            inputStream.close();

            if (LOG.isLoggable(Level.FINE))
            {
                // -DM Hex.toHexString
                LOG.fine("new file digest: " + Hex.toHexString(newDigest));
            }

            if (Arrays.constantTimeAreEqual(currentDigest, newDigest))
            {
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine("existing file already exists and is the same");
                }
                // Same file so do nothing!
                return dest;
            }

            if (LOG.isLoggable(Level.FINE))
            {
                LOG.fine("existing file is different and will be replaced");
            }

            inputStream = NativeLoader.class.getResourceAsStream(inJarPath);
        }

        FileOutputStream fos = new FileOutputStream(dest);
        Streams.pipeAll(inputStream, fos);
        fos.flush();
        fos.close();
        inputStream.close();
        return dest;
    }

}