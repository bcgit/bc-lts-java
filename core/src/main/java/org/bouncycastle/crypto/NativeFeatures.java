package org.bouncycastle.crypto;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * The native methods of this class are used to determine the native features that are supported.
 * UnsatisfiedLinkError are ignored, and it is assumed that the feature is not available at that time.
 */
class NativeFeatures
{
    private static final Logger NATIVE_FEATURE_LOG = Logger.getLogger(NativeFeatures.class.getName());
    static boolean hasCTRHardwareSupport()
    {
        try
        {
            return nativeCTR();
        }
        catch (UnsatisfiedLinkError ule)
        {
            //
        }
        if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
            NATIVE_FEATURE_LOG.log(Level.FINE,"native ctr not supported");
        }
        return false;
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
            //
        }
        if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
            NATIVE_FEATURE_LOG.log(Level.FINE,"native cfb not supported");
        }
        return false;
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
            //
        }
        if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
            NATIVE_FEATURE_LOG.log(Level.FINE,"native cbc not supported");
        }
        return false;
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
            //
        }
        if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
            NATIVE_FEATURE_LOG.log(Level.FINE,"native aes not supported");
        }
        return false;
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
            if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
                NATIVE_FEATURE_LOG.log(Level.FINE,"native gcm not supported");
            }
            return false;
        }
    }

    private static native boolean nativeGCM();


    static boolean hasHardwareRand()
    {
        try
        {
            return nativeRand();
        }
        catch (UnsatisfiedLinkError ule)
        {
            //
        }
        if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
            NATIVE_FEATURE_LOG.log(Level.FINE,"native rand not supported");
        }
        return false;
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
            //
        }
        if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
            NATIVE_FEATURE_LOG.log(Level.FINE,"native seed not supported");
        }
        return false;
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
            //
        }
        if (NATIVE_FEATURE_LOG.isLoggable(Level.FINE)) {
            NATIVE_FEATURE_LOG.log(Level.FINE,"native sha not supported");
        }
        return false;
    }

    private static native boolean nativeSHA2();




    private static native boolean nativeRSA();
}