package org.bouncycastle.crypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.jar.JarException;
import java.util.logging.Logger;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.io.Streams;

class NativeLoader
{
    private static final Logger LOG = Logger.getLogger(NativeLoader.class.getName());
    public static final String BC_LIB_CPU_VARIANT = "org.bouncycastle.native.cpu_variant";


    private static boolean nativeLibsAvailableForSystem = false;
    private static boolean nativeInstalled = false;
    private static boolean nativeEnabled = true;
    private static String nativeStatusMessage = "component load not attempted";

    private static String selectedVariant = null;

    private static boolean loadCalled = false;
    private static String nativeBuildDate = null;


    /**
     * Hardware Aes ECB is supported.
     *
     * @return true if basic ecb is supported
     */
    public static boolean hasHardwareAesECB()
    {
        return NativeLoader.isNativeAvailable() && NativeFeatures.hasAESHardwareSupport();
    }

    /**
     * Hardware Aes CBC is supported.
     *
     * @return true if supported
     */
    public static boolean hasHardwareAesCBC()
    {
        return NativeLoader.isNativeAvailable() && NativeFeatures.hasAESHardwareSupport();
    }

    public static boolean hasHardwareAesGCM()
    {
        return NativeLoader.isNativeAvailable() && NativeFeatures.hasGCMHardwareSupport();
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
     * @param enabled when true will disable the use of native extensions.
     */
    static synchronized void setNativeEnabled(boolean enabled)
    {
        nativeEnabled = enabled;
    }

    static synchronized String getStatusMessage()
    {
        return nativeStatusMessage;
    }

    static synchronized String getNativeBuildDate()
    {
        return nativeBuildDate;
    }

    public static synchronized String getVariant()
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
        } catch (Exception ex)
        {
            return null;
        }
        return value;
    }


    static File installLib(String name, String libPathSegment, String jarPath, File bcLibPath, Set<File> filesInInstallLocation)
            throws Exception
    {

        //
        // Copy nominated dep for library into bcLibPath
        //

        String libLocalName = System.mapLibraryName(name);
        File libToLoad = copyFromJar(libPathSegment + "/" + libLocalName, bcLibPath, libLocalName);

        filesInInstallLocation.remove(libToLoad);


        return libToLoad;
    }

    public static synchronized void loadDriver()
    {
        try
        {
            if (loadCalled)
            {
                return;
            }

            bootNative();

        } finally
        {
            loadCalled = true;
        }
    }


    public static synchronized void bootNative()
    {

        String forcedVariant = Properties.getPropertyValue(BC_LIB_CPU_VARIANT);


        // No variants defined at all, or a
        // single variant defined that is java only.
        //
        if ("java".equals(forcedVariant))
        {
            nativeInstalled = false;
            nativeStatusMessage = "java support only";
            return;
        }

        String arch_ = Strings.toLowerCase(System.getProperty("os.arch", ""));
        String os_ = Strings.toLowerCase(System.getProperty("os.name", ""));
        String platform = null;
        String arch = null;
        String ldPathEnvVar = null;

        if (os_.contains("darwin") || os_.contains("mac os"))
        {
            platform = "darwin";
            ldPathEnvVar = "DYLIB_LIBRARY_PATH";
        } else if (os_.contains("linux"))
        {
            platform = "linux";
            ldPathEnvVar = "LD_LIBRARY_PATH";
        }


        if (platform == null)
        {
            nativeStatusMessage = "OS '" + os_ + "' is not supported.";
            return;
        }

        if ((arch_.contains("x86") || arch_.contains("amd")) && arch_.contains("64"))
        {
            arch = "x86_64";
        }


        if (arch == null)
        {
            nativeStatusMessage = "architecture '" + arch_ + "' is not supported";
            return;
        }


        File bcFipsLibPath;
        try
        {

            //
            // Create a temporary file.
            //
            File tf = File.createTempFile("bc-jni", "");

            //
            // Create a directory using that file as a stem
            //
            final File tmpDir = new File(tf.getParent(), tf.getName() + "-libs");
            if (!tmpDir.mkdirs())
            {
                nativeInstalled = false;
                nativeStatusMessage = "unable to create temp directory for jni libs: " + tmpDir;
                return;
            }

            //
            // Delete original file.
            //
            if (!tf.delete())
            {
                nativeInstalled = false;
                nativeStatusMessage = "unable to delete initial temporary file: " + tf;
                return;
            }

            //
            // Shutdown hook clean up installed libraries.
            //
            Runtime.getRuntime().addShutdownHook(new Thread(new Runnable()
            {
                @Override
                public void run()
                {
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
                        LOG.warning(" failed to delete: " + tmpDir.getAbsolutePath());
                    } else
                    {
                        LOG.warning("cleaned up: " + tmpDir.getAbsolutePath());
                    }
                }
            }));

            bcFipsLibPath = tmpDir.getCanonicalFile();

        } catch (Exception ex)
        {
            nativeInstalled = false;
            nativeStatusMessage = "failed because it was not able to create a temporary file in 'java.io.tmpdir' " + ex.getMessage();
            return;
        }


        //
        // We track all the existing files in the installation location.
        // During installation, we remove them from this set if they have been replaced.
        // if any files are remaining in the set then there were unaccounted for files in
        // the installation location, and we cannot start the module.
        //
        Set<File> filesInInstallLocation = new HashSet<File>();

        for (File f : bcFipsLibPath.listFiles())
        {
            filesInInstallLocation.add(f);
        }


        //
        // Point to the directory in the jar where the native libs are located.
        //
        String jarDir = String.format("/native/%s/%s", platform, arch);


        //
        // Look for a probe library, it matches the platform and architecture.
        // It needs to exist regardless of any forced variant, if it does not exist
        // any forced variant is not going to function anyway.
        //
        String probeLibInJarPath = String.format("/native/%s/%s/probe", platform, arch);

        if (forcedVariant != null)
        {
            selectedVariant = forcedVariant;
        } else
        {
            try
            {
                // Install probe lib
                final File lib = installLib("bc-probe", probeLibInJarPath, jarDir, bcFipsLibPath, filesInInstallLocation);

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

            } catch (Exception ex)
            {
                nativeStatusMessage = "probe lib failed to load " + ex.getMessage();
                nativeInstalled = false;
                return;
            }

            selectedVariant = VariantSelector.getBestVariantName();
        }


        String variantPathInJar = String.format("/native/%s/%s/%s", platform, arch, selectedVariant);//  variantPaths.get(selectedVariant);
        if (variantPathInJar == null)
        {
            nativeStatusMessage = String.format("variant %s is not available for installation", selectedVariant);
            nativeInstalled = false;
            return;
        }

        try
        {
            //
            // Derive the suffix it is the last part of the variant name
            // eg: linux-x86_64-sse has a suffix of "sse"
            //

            final File lib = installLib("bc-components-" + selectedVariant, variantPathInJar, jarDir, bcFipsLibPath, filesInInstallLocation);


            //
            // If not empty we have unexpected files in the library path
            //
            if (!filesInInstallLocation.isEmpty())
            {
                nativeStatusMessage = String.format("unexpected files in %s: %s", bcFipsLibPath.toString(), collectionToString(filesInInstallLocation));
                nativeInstalled = false;
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

        } catch (Exception ex)
        {
            nativeStatusMessage = "native capabilities lib failed to load " + ex.getMessage();
            nativeInstalled = false;
            return;
        }

        String reportedVariantName = NativeLibIdentity.getLibraryIdent();

        if (!selectedVariant.equals(reportedVariantName))
        {
            nativeStatusMessage = String.format("loaded native library variant is %s but the requested library variant is %s", NativeLibIdentity.getLibraryIdent(), selectedVariant);
            nativeInstalled = false;
            return;
        }


        nativeBuildDate = NativeLibIdentity.getNativeBuiltTimeStamp();
        nativeLibsAvailableForSystem = true;
        nativeStatusMessage = "successfully loaded";
        nativeInstalled = true;
    }


    /**
     * Turn a collection into a flat list of strings, java 1.6 compatible.
     *
     * @return A string
     */
    private static String collectionToString(Collection collection)
    {
        boolean comma = false;
        StringBuilder sb = new StringBuilder();
        for (Object o : collection)
        {
            if (comma)
            {
                sb.append(",");
            } else
            {
                comma = true;
            }
            sb.append(o.toString());
        }

        return sb.toString();
    }

    private static byte[] takeSHA256Digest(InputStream in)
    {
        try
        {
            byte[] buf = new byte[65535];
            SavableDigest dig = new SHA256Digest();
            int len;
            while ((len = in.read(buf)) >= 0)
            {
                dig.update(buf, 0, len);
            }
            byte[] res = new byte[dig.getDigestSize()];
            dig.doFinal(res, 0);
            return res;
        } catch (IOException ex)
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
            FileInputStream fin = new FileInputStream(dest);
            byte[] currentDigest = takeSHA256Digest(fin);
            fin.close();

            byte[] newDigest = takeSHA256Digest(inputStream);
            inputStream.close();

            if (Arrays.constantTimeAreEqual(currentDigest, newDigest))
            {
                // Same file so do nothing!
                return dest;
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
