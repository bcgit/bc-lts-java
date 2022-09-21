package org.bouncycastle.util;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;

public class DumpInfo
{
    public static void main(String args)
    {
        CryptoServicesRegistrar.getNativeServices();

        //-DM System.out.println
        //-DM System.out.println
        //-DM System.out.println
        //-DM System.out.println
        System.out.println("BC-JAVA");
        System.out.println("Native Status: " + NativeServices.getStatusMessage());
        System.out.println("Native Variant: " + NativeServices.getVariant());
        System.out.println("Native Features: " + NativeServices.getFeatureSet());
    }
}
