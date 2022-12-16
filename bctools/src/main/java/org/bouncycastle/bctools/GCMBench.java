package org.bouncycastle.bctools;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.SecureRandom;

import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CBCModeCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

public class GCMBench
{




    public static void main(String[] args)
        throws Exception
    {

        int blockSize = 8;
        int maxBlocks = 4200;
        int repeats = 1000;
        int step = 10;
        String output = "cbc.csv";

        for (int t = 0; t < args.length; t++)
        {
            if ("-blockSize".equals(args[t]))
            {
                t++;
                blockSize = asInt(args, t, "-blockSize");
            }
            else if ("-maxBlocks".equals(args[t]))
            {
                t++;
                maxBlocks = asInt(args, t, "-maxBlocks");
            }
            else if ("-repeats".equals(args[t]))
            {
                t++;
                repeats = asInt(args, t, "-repeats");
            }
            else if ("-output".equals(args[t]))
            {
                t++;
                output = asString(args, t, "-output");
            } else if ("-variant".equals(args[t])) {
                t++;
                System.setProperty("org.bouncycastle.native.cpu_variant",asString(args, t, "-variant"));
            }
        }


        GCMModeCipher gcmEnc = GCMBlockCipher.newInstance(AESEngine.newInstance());
        GCMModeCipher gcmDec = GCMBlockCipher.newInstance(AESEngine.newInstance());


        System.out.println(NativeServices.getVariant()+" "+ NativeServices.getBuildDate() +" "+NativeServices.getStatusMessage());

        SecureRandom secureRandom = new SecureRandom();


        FileWriter fw = new FileWriter(output);
        PrintWriter pw = new PrintWriter(fw);

        pw.println("Keysize\tEncryption\tLength\tBPS");

        for (int ks : new int[]{16,24,32}) //, 24, 32})
        {
            byte[] key = new byte[ks];
            byte[] iv = new byte[12];
            for (int a = 1; a <= maxBlocks; a += (a < 10) ? 1 : 16)
            {
                double sumEnc = 0;
                double sumDec = 0;
                double count = 0;



                long ts = 0;
                long te = 0;

                byte[] msg = new byte[blockSize * a];
                secureRandom.nextBytes(msg);


                byte[] cipherText = new byte[msg.length+16];
                byte[] finalResult = new byte[msg.length];



                for (int b = 0; b < repeats; b++)
                {

                    secureRandom.nextBytes(key);
                    secureRandom.nextBytes(iv);

                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(key), iv);

                    gcmEnc.init(true, piv);
                    gcmDec.init(false, piv);



                    ts = System.nanoTime();
                    int l = gcmEnc.processBytes(msg, 0, msg.length, cipherText, 0);
                    gcmEnc.doFinal(cipherText,l);
                    te = System.nanoTime();
                    sumEnc += te - ts;

                    ts = System.nanoTime();

                    l = gcmDec.processBytes(cipherText, 0, cipherText.length, finalResult, 0);
                    gcmDec.doFinal(finalResult,l);
                    te = System.nanoTime();
                    sumDec += te - ts;

                    count++;

                    if (!Arrays.areEqual(finalResult, msg))
                    {

                        //-DM System.out.println
                        System.out.println("\n");


                        // -DM System.out.println
                        // -DM Hex.toHexString
                        System.out.println("MSG: " + Hex.toHexString(msg));
                        // -DM System.out.println
                        // -DM Hex.toHexString
                        System.out.println("KEY: " + Hex.toHexString(key));
                        // -DM System.out.println
                        // -DM Hex.toHexString
                        System.out.println("IV: " + Hex.toHexString(iv));
                        // -DM System.out.println
                        // -DM Hex.toHexString
                        System.out.println("Final Result: " + Hex.toHexString(finalResult));

                        // -DM System.out.println
                        System.out.println("CBC did not round trip");
                        //-DM System.exit
                        System.exit(1);
                    }
                }

                double encAvgNano = sumEnc / count;
                double decAvgNano = sumDec / count;

                double bytesPerSecondEnc = (((double)msg.length) / encAvgNano) * 1000000000.0;
                double bytesPerSecondDec = (((double)msg.length) / decAvgNano) * 1000000000.0;

                // -DM printf
                pw.printf("%d\ttrue\t%d\t%.2f\n",ks, msg.length, bytesPerSecondEnc);
                // -DM printf
                pw.printf("%d\tfalse\t%d\t%.2f\n",ks,  msg.length, bytesPerSecondDec);


            }
        }
        pw.flush();
        pw.close();
    }

    private static int asInt(String[] args, int index, String name)
    {
        int i = 0;
        if (index >= args.length)
        {
            //-DM System.out.println
            System.out.println(name + " is not defined.");
            //-DM System.exit
            System.exit(1);
        }
        try
        {
            i = Integer.parseInt(args[index].trim());
        }
        catch (Exception ex)
        {
            //-DM System.out.println
            System.out.println("count not parse " + name);
            //-DM System.exit
            System.exit(1);
        }
        return i;
    }

    private static String asString(String[] args, int index, String name)
    {
        String s = "";
        if (index >= args.length)
        {
            //-DM System.out.println
            System.out.println(name + " is not defined.");
            //-DM System.exit
            System.exit(1);
        }

        s = args[index].trim();
        if (s.isEmpty())
        {
            //-DM System.out.println
            System.out.println("is empty " + name);
            //-DM System.exit
            System.exit(1);
        }
        return s;
    }

}
