package org.bouncycastle.util;

public class NativeFeatures
{
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
        return false;
    }

    private static native boolean nativeAES();


    static boolean hasGCMHardwareSupport()
    {
        try
        {
            return nativeCMUL() && nativeAES();
        }
        catch (UnsatisfiedLinkError ule)
        {
            return false;
        }
    }

    private static native boolean nativeCMUL();


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
            ule.printStackTrace();
            //
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
        return false;
    }

    private static native boolean nativeSHA2();
}
