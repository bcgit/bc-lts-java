package org.bouncycastle.crypto;

/**
 * Native methods in this class are implemented by the specific native lib version
 * to identify the library.
 */
class NativeLibIdentity
{
    static String getLibraryIdent()
    {
        try
        {
            return getLibIdent();
        } catch (UnsatisfiedLinkError ule)
        {
            return ule.getMessage();
        }
    }

    private static native String getLibIdent();

    static String getNativeBuiltTimeStamp()
    {
        try
        {
            return getBuiltTimeStamp();
        } catch (UnsatisfiedLinkError ule)
        {
            return ule.getMessage();
        }
    }

    private static native String getBuiltTimeStamp();
}
