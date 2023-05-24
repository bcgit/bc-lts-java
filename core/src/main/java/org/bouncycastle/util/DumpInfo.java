package org.bouncycastle.util;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;

public class DumpInfo
{

    private static final String newLine = "\n";

    public static void main(String[] args)
    {
        //-DM System.out.println
        //-DM System.out.println
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
            System.out.println("");


            String[][] result = nativeServices.getVariantSelectionMatrix();
            StringBuffer sBld = new StringBuffer();
            if (result.length > 0)
            {
                sBld.append(newLine);
                sBld.append("CPU Features and Variant availability.");
                sBld.append(newLine);
                sBld.append("--------------------------------------------------------------------------------");
                sBld.append(newLine);
                sBld.append(pad("Variant", 10));
                sBld.append(pad("CPU features + or -:", 50));
                sBld.append(pad("Supported", 20));

                sBld.append(newLine);
                sBld.append("--------------------------------------------------------------------------------");
                sBld.append(newLine);
                for (String[] parts : result)
                {

                    String title = pad(parts[0], 10);
                    String cpuFeatures = "";
                    for (int t = 1; t < parts.length - 1; t++)
                    {
                        cpuFeatures += parts[t];
                        cpuFeatures += " ";
                    }
                    cpuFeatures = pad(cpuFeatures.trim(), 50);

                    String status = parts[parts.length - 1];

                    sBld.append(title);
                    sBld.append(cpuFeatures);
                    sBld.append(status);
                    sBld.append(newLine);
                }

                sBld.append(newLine);
            }
            System.out.println(sBld);

        }


    }

    private static String pad(String left, int len)
    {
        StringBuilder sb = new StringBuilder();
        sb.append(left);
        for (int t = 0; t < len - left.length(); t++)
        {
            sb.append(" ");
        }
        return sb.toString();
    }


}
