package org.bouncycastle.crypto;

class NativeFeatures
{
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
