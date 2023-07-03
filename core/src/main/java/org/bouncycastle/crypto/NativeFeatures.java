package org.bouncycastle.crypto;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The native methods of this class are used to determine the native features that are supported.
 * UnsatisfiedLinkError are ignored, and it is assumed that the feature is not available at that time.
 */
class NativeFeatures
{
    private static final Logger LOG = Logger.getLogger(NativeFeatures.class.getName());

    static boolean hasCTRHardwareSupport()
    {
        try
        {
            return nativeCTR();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native ctr exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeCTR();


    static boolean hasCFBHardwareSupport()
    {
        try
        {
            return nativeCFB();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native cfb exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    native private static boolean nativeCFB();

    static boolean hasCBCHardwareSupport()
    {
        try
        {
            return nativeCBC();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native cbc exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private native static boolean nativeCBC();


    static boolean hasAESHardwareSupport()
    {
        try
        {
            return nativeAES();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native aes exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeAES();


    static boolean hasGCMHardwareSupport()
    {
        try
        {
            return nativeGCM();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native gcm exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeGCM();




    static boolean hasCCMHardwareSupport()
    {
        try
        {
            return nativeCCM();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.WARNING))
            {
                LOG.log(Level.WARNING, "native ccm exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeCCM();



    static boolean hasHardwareRand()
    {
        try
        {
            return nativeRand();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native rand exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeRand();

    static boolean hasHardwareSeed()
    {
        try
        {
            return nativeSeed();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native seed exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeSeed();

    static boolean hasHardwareSHA()
    {
        try
        {
            return nativeSHA2();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native sha exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    static boolean hasMultiplyAcc()
    {
        try
        {
            return nativeMulAcc();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native multiply and accumulate exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }


    private static native boolean nativeSHA2();

    private static native boolean nativeMulAcc();

    private static native boolean nativeRSA();
}