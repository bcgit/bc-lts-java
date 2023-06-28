package org.bouncycastle.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
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

    private static String selectedVariant = null;

    private static boolean javaSupportOnly = true;

    private static final NativeServices nativeServices = new DefaultNativeServices();

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
                    File dir = null;
                    long time = System.nanoTime();
                    for (int t = 0; t < 1000; t++)
                    {
                        dir = new File(ioTmpDir, "bc-lts-jni" + Long.toString(time + t, 32) + "-libs");
                        if (dir.mkdirs())
                        {
                            break;
                        }
                        dir = null;
                        Thread.sleep(time % 97);
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
                            if (tmpDir.isDirectory())
                            {
                                for (File f : tmpDir.listFiles())
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

        for (File f : bcLtsLibPath.listFiles())
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
                probeLibPrefix = "bc-probe-be";
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
        catch (Exception ex)
        {
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
            javaSupportOnly = true;
            nativeInstalled = false;
            nativeStatusMessage = "probe returned no suitable CPU features, java support only";
            LOG.fine("exited with " + nativeStatusMessage);
            return;
        }

        if (forcedVariant != null)
        {
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
        catch (Exception ex)
        {
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