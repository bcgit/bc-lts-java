package org.bouncycastle.util;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;

public class DumpInfo
{
    public static void main(String[] args)
    {
        //-DM System.out.println
        //-DM System.out.println
        //-DM System.out.println
        //-DM System.out.println
        //-DM System.out.println
        System.out.println(CryptoServicesRegistrar.getInfo());

        if (CryptoServicesRegistrar.isNativeEnabled())
        {
            NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();

            System.out.println("Native Build Date: " + nativeServices.getBuildDate());
            System.out.println("Native Status: " + nativeServices.getStatusMessage());
            System.out.println("Native Variant: " + nativeServices.getVariant());
            System.out.println("Native Features: " + String.join(" ", nativeServices.getFeatureSet()));
        }
    }
}
