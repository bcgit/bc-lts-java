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
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native ccm exception: " + ule.getMessage(), ule);
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

    static boolean hasHardwareSHA256()
    {
        try
        {
            return nativeSHA256();
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

    static boolean hasHardwareSHA224()
    {
        try
        {
            return nativeSHA224();
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

    static boolean hasHardwareSHA384()
    {
        try
        {
            return nativeSHA384();
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


    static boolean hasHardwareSHA512()
    {
        try
        {
            return nativeSHA512();
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


    static boolean hasSHA3()
    {
        try
        {
            return nativeSHA3();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native sha3 exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeSHA3();

    private static native boolean nativeSHA256();

    private static native boolean nativeSHA224();

    private static native boolean nativeSHA384();

    private static native boolean nativeSHA512();

    private static native boolean nativeMulAcc();

    private static native boolean nativeRSA();
}