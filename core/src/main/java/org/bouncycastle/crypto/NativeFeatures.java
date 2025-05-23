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

    static boolean hasGCMSIVHardwareSupport()
    {
        try
        {
            return nativeGCMSIV();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native gcm-siv exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeGCMSIV();


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

    static boolean hasCCMPCHardwareSupport()
    {
        try
        {
            return nativeCCMPC();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.WARNING))
            {
                LOG.log(Level.WARNING, "native ccm packet cipher exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeCCMPC();

    static boolean hasCBCPCHardwareSupport()
    {
        try
        {
            return nativeCBCPC();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.WARNING))
            {
                LOG.log(Level.WARNING, "native cbc packet cipher exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeCBCPC();

    static boolean hasCFBPCHardwareSupport()
    {
        try
        {
            return nativeCFBPC();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.WARNING))
            {
                LOG.log(Level.WARNING, "native cfb packet cipher exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeCFBPC();

    static boolean hasCTRPCHardwareSupport()
    {
        try
        {
            return nativeCTRPC();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.WARNING))
            {
                LOG.log(Level.WARNING, "native ctr packet cipher exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeCTRPC();

    static boolean hasGCMPCHardwareSupport()
    {
        try
        {
            return nativeGCMPC();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.WARNING))
            {
                LOG.log(Level.WARNING, "native gcm packet cipher exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeGCMPC();

    static boolean hasGCMSIVPCHardwareSupport()
    {
        try
        {
            return nativeGCMSIVPC();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.WARNING))
            {
                LOG.log(Level.WARNING, "native gcm-siv packet cipher exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    private static native boolean nativeGCMSIVPC();

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

    static boolean hasSHAKE()
    {
        try
        {
            return nativeSHAKE();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native shake exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }

    static boolean hasSlhDSASha256()
    {
        try
        {
            return nativeSlhDSASha256();
        }
        catch (UnsatisfiedLinkError ule)
        {
            if (LOG.isLoggable(Level.FINE))
            {
                LOG.log(Level.FINE, "native shake exception: " + ule.getMessage(), ule);
            }
            return false;
        }
    }


    private static native boolean nativeSHAKE();

    private static native boolean nativeSHA3();

    private static native boolean nativeSHA256();

    private static native boolean nativeSHA224();

    private static native boolean nativeSHA384();

    private static native boolean nativeSHA512();

    private static native boolean nativeMulAcc();

    private static native boolean nativeRSA();

    private static native boolean nativeSlhDSASha256();
}