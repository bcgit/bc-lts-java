//package org.bouncycastle.benchmark_new;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
/*
(export LD_LIBRARY_PATH=/tmp/bcfipslibs; java -Dorg.bouncycastle.native.library_path=/tmp/bcfipslibs -cp jars/bc-fips-2.0.1-SNAPSHOT.jar:./benchmark/build/libs/bc-fips-benchmark-2.0.1-SNAPSHOT.jar org.bouncycastle.benchmark.Benchmark)
 */


public class Benchmark
{
    private static double SECONDS = 1000000000.0;


    public static void main(String[] args)
        throws Exception
    {
//        try
//        {
//            Security.addProvider(new BouncyCastleProvider());
//        }
//        catch (Exception e)
//        {
//            e.printStackTrace();
//        }

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
//
//
//        FipsStatus.isReady();


        List<Sample> sampleList = new ArrayList<>();
        String name = null;
        String[] header = null;
        String fs = "";
//        try {
////            fs = FipsStatus.getNativeFeatureString();
//        } catch (NoSuchMethodError sne) {
//
//            fs = "";
//        }


        if (args.length == 0)
        {
            System.err.println("Expected gcm, ecb, cbc, sha");
            System.exit(1);
        }
        else
        {
            if (args[0].equals("sha"))
            {
                benchmarkSHA256(1024 * 256, sampleList);
                header = new String[]{"Label", "Message Size", "Throughput B/s"};
                if (fs.contains("SHA"))
                {
                    name = "SHANative";
                }
                else
                {
                    name = "SHAJava";
                }
            }
            else if (args[0].equals("gcm"))
            {
                benchmarkGCM(1024 * 2048, sampleList);

                header = new String[]{"Label", "Message Size", "Throughput B/s"};
                if (fs.contains("AES/GCM"))
                {
                    name = "GCMNative";
                }
                else
                {
                    name = "GCMJava";
                }
            }
            else if (args[0].equals("cbc"))
            {
                header = new String[]{"Label", "Message Size", "Throughput B/s"};
                benchmarkCBC(1024 * 256, sampleList);

                if (fs.contains("AES"))
                {
                    name = "CBCNative";
                }
                else
                {
                    name = "CBCJava";
                }
            }
            else if (args[0].equals("ecb"))
            {
                header = new String[]{"Label", "Message Size", "Throughput B/s"};
                benchmarkECB(1024 * 384, sampleList);

                if (fs.contains("AES"))
                {
                    name = "ECBNative";
                }
                else
                {
                    name = "ECBJava";
                }
            }
            else if (args[0].equals("ecb_jce"))
            {
                header = new String[]{"Label", "Message Size", "Throughput B/s"};
                benchmarkECBJCE(1024 * 384, sampleList);

                if (fs.contains("AES"))
                {
                    name = "ECBNative_JCE";
                }
                else
                {
                    name = "ECBJava_JCE";
                }
            }
            else if (args[0].equals("cfb"))
            {
                header = new String[]{"Label", "Message Size", "Throughput B/s"};
                benchmarkCFB(1024 * 384, sampleList);

                if (fs.contains("AES"))
                {
                    name = "CFBNative_JCE";
                }
                else
                {
                    name = "CFBJava_JCE";
                }
            }
            else if (args[0].equals("ctr"))
            {
                header = new String[]{"Label", "Message Size", "Throughput B/s"};
                benchmarkCTR(1024 * 384, sampleList);

                if (fs.contains("AES"))
                {
                    name = "CTRNative_JCE";
                }
                else
                {
                    name = "CTRJava_JCE";
                }
            }
            else
            {
                System.err.println("Expected gcm, ecb, cbc, sha");
                System.exit(1);
            }

            name = name + "-" + args[1];
//            name = name + "-" + FipsStatus.getNativeLibraryIdent();


            FileWriter fw = new FileWriter(name + ".csv");
            PrintWriter pw = new PrintWriter(fw);

            pw.println(java.util.Arrays.asList(header).stream().map(it -> "\"" + it + "\"").collect(Collectors.joining(",")));

            for (Sample s : sampleList)
            {
                pw.println(s.asCSV());
            }
            pw.flush();
            pw.close();


        }

    }


    public static void benchmarkSHA256(int maxSize, List<Sample> dataPoints)
        throws Exception
    {
        int msgSize = 1;
        for (; msgSize < maxSize; )
        {
            byte[] msg = new byte[msgSize];
            Arrays.fill(msg, (byte)msgSize);

//            FipsDigestOperatorFactory<FipsSHS.Parameters> factory = new FipsSHS.OperatorFactory<FipsSHS.Parameters>();
//            OutputDigestCalculator<FipsSHS.Parameters> calculator = factory.createOutputDigestCalculator(FipsSHS.SHA256);
            MessageDigest digestStream = MessageDigest.getInstance("SHA-256");

            double accumulator = 0;
            double samples = 0;
            for (int k = 0; k < 64; k++)
            {
//                OutputStream digestStream = calculator.getDigestStream();
                long ts = System.nanoTime();
                digestStream.update(msg);
                digestStream.digest();
//                digestStream.write(msg);
//                digestStream.close();
//                calculator.getDigest();
                long te = System.nanoTime();

                double deltaNano = (te - ts);
                double deltaSecond = deltaNano / SECONDS;
                double bps = ((double)msg.length) / deltaSecond;

                accumulator += bps;
                samples += 1;
                msg[0] += 1;
            }


//            dataPoints.add(new Sample("SHA256-" + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulator / samples) / 1024.0, "B/s"));
            dataPoints.add(new Sample("SHA256-", msg.length, (accumulator / samples) / 1024.0, "B/s"));

            if (msgSize < 128)
            {
                msgSize += 1;
            }
            else if (msgSize < 2048)
            {
                msgSize += 16;
            }
            else if (msgSize < 102400)
            {
                msgSize += 256;
            }
            else
            {
                msgSize += 1024;
            }

        }
    }

    public static void benchmarkGCM(int maxSize, List<Sample> dataPoints)
        throws Exception
    {

        SecureRandom random = new SecureRandom();
        int msgSize = 1;
        ByteArrayOutputStream ct = new ByteArrayOutputStream(2048 * 1024);
        ByteArrayOutputStream pt = new ByteArrayOutputStream(2048 * 1024);
        for (; msgSize < maxSize; )
        {
            byte[] msg = new byte[msgSize];


            Arrays.fill(msg, (byte)msgSize);

            int[] keySizes = new int[]{16, 24, 32};

            for (int ks : keySizes)
            {
                byte[] key = new byte[ks];
                random.nextBytes(key);
                byte[] nonce = Hex.decode("58d2240f580a31c1d24948e9");
//                FipsAEADOperatorFactory<FipsAES.AuthParameters> fipsSymmetricFactory = new FipsAES.AEADOperatorFactory();
//                FipsOutputAEADEncryptor<Cipher.AuthParameters> outputEncryptor = fipsSymmetricFactory.createOutputAEADEncryptor(
//                        new SymmetricSecretKey(FipsAES.GCM, key), FipsAES.GCM.withMACSize(128).withIV(nonce));
//                FipsOutputAEADDecryptor<FipsAES.AuthParameters> inputEncryptor = fipsSymmetricFactory.createOutputAEADDecryptor(
//                        new SymmetricSecretKey(FipsAES.GCM, key), FipsAES.GCM.withMACSize(128).withIV(nonce));
                double accumulatorEnc = 0;
                double accumulatorDec = 0;
                double samples = 1;
                double bpsMaxEnc = Double.MIN_VALUE;
                double bpsMaxDec = Double.MIN_VALUE;
                for (int k = 0; k < 30; k++)
                {
                    ct.reset();
                    //OutputStream enc = outputEncryptor.getEncryptingStream(ct);
                    try
                    {
                        Cipher enc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                        KeyGenerator kGen = KeyGenerator.getInstance("AES", "BC");
                        Key keys = kGen.generateKey();
                        enc.init(Cipher.ENCRYPT_MODE, keys, new AEADParameterSpec(nonce, 32));
                        long ts = System.nanoTime();
                        byte[] c = enc.update(msg);
                        byte[] d = enc.doFinal();
//                    enc.write(msg);
//                    enc.close();
                        long te = System.nanoTime();
                        if (c != null)
                        {
                            ct.write(c);
                        }

                        ct.write(d);
                        double deltaNano = (te - ts);
                        double deltaSecond = deltaNano / SECONDS;
                        double bps = ((double)msg.length) / deltaSecond;
                        if (bps > bpsMaxEnc)
                        {
                            bpsMaxEnc = bps;
                        }
                        accumulatorEnc = bpsMaxEnc;
                        pt.reset();
                        //OutputStream os = inputEncryptor.getDecryptingStream(pt);
                        enc = Cipher.getInstance("AES/GCM/NoPadding", "BC");
                        enc.init(Cipher.DECRYPT_MODE, keys, new AEADParameterSpec(nonce, 32));
                        d = ct.toByteArray();
                        ts = System.nanoTime();
                        enc.update(d);
                        enc.doFinal();
//                    os.write(d);
//                    os.close();
                        te = System.nanoTime();
//                    if (!MessageDigest.isEqual(pt.toByteArray(), msg)) {
//                        throw new RuntimeException("gcm pt not equal");
//                    }
                        deltaNano = (te - ts);
                        deltaSecond = deltaNano / SECONDS;
                        bps = ((double)msg.length) / deltaSecond;
                        if (bps > bpsMaxDec)
                        {
                            bpsMaxDec = bps;
                        }
                        accumulatorDec = bpsMaxDec;
                        //   samples += 1;
                        msg[0] += 1;
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                    }


                }
//                dataPoints.add(new Sample("Encrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
//                dataPoints.add(new Sample("Decrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Encrypt " + ks + " ", msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Decrypt " + ks + " ", msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));


                if (msgSize < 128)
                {
                    msgSize += 1;
                }
                else if (msgSize < 2048)
                {
                    msgSize += 16;
                }
                else
                {
                    msgSize += 2048;
                }
            }
        }
    }


    public static void benchmarkCBC(int maxSize, List<Sample> dataPoints)
        throws Exception
    {
        SecureRandom random = new SecureRandom();
        int msgSize = 16;
        for (; msgSize < maxSize; )
        {
            byte[] msg = new byte[msgSize];
            Arrays.fill(msg, (byte)msgSize);

            int[] keySizes = new int[]{16, 24, 32};

            for (int ks : keySizes)
            {
                byte[] key = new byte[ks];
                random.nextBytes(key);

                byte[] nonce = Hex.decode("58d2240f580a31c1d24948e901020304");


//                FipsAES.OperatorFactory fipsSymmetricFactory = new FipsAES.OperatorFactory();
//
//                FipsOutputEncryptor<FipsAES.Parameters> outputEncryptor = fipsSymmetricFactory.createOutputEncryptor(
//                        new SymmetricSecretKey(FipsAES.CBC, key), FipsAES.CBC.withIV(nonce));
//
//
//                FipsOutputDecryptor<FipsAES.Parameters> inputEncryptor = fipsSymmetricFactory.createOutputDecryptor(
//                        new SymmetricSecretKey(FipsAES.CBC, key), FipsAES.CBC.withIV(nonce));


                double accumulatorEnc = 0;
                double accumulatorDec = 0;
                double samples = 1;

                double bpsMaxEnc = Double.MIN_VALUE;
                double bpsMaxDec = Double.MIN_VALUE;
                Cipher enc = Cipher.getInstance("AES/CBC/NoPadding", "BC");
                Cipher dec = Cipher.getInstance("AES/CBC/NoPadding", "BC");
                ByteArrayOutputStream pt = new ByteArrayOutputStream(256 * 1024);
                ByteArrayOutputStream ct = new ByteArrayOutputStream(256 * 1024);
                for (int k = 0; k < 10; k++)
                {
                    ct.reset();
                    //OutputStream enc = outputEncryptor.getEncryptingStream(ct);
                    //try
                    {
                        KeyGenerator kGen = KeyGenerator.getInstance("AES", "BC");
                        Key keys = kGen.generateKey();
                        enc.init(Cipher.ENCRYPT_MODE, keys, new IvParameterSpec(nonce));

                        long ts = System.nanoTime();
                        byte[] c = enc.update(msg);
                        byte[] d = enc.doFinal();
                        long te = System.nanoTime();
                        if (c != null)
                        {
                            ct.write(c);
                        }
                        ct.write(d);
                        double deltaNano = (te - ts);
                        double deltaSecond = deltaNano / SECONDS;
                        double bps = ((double)msg.length) / deltaSecond;
                        if (bps > bpsMaxEnc)
                        {
                            bpsMaxEnc = bps;
                        }
                        accumulatorEnc = bpsMaxEnc;
                        pt.reset();
                        //OutputStream os = inputEncryptor.getDecryptingStream(pt);
                        dec.init(Cipher.DECRYPT_MODE, keys, new IvParameterSpec(nonce));
                        d = ct.toByteArray();
                        ts = System.nanoTime();
                        dec.update(d);
                        dec.doFinal();
                        te = System.nanoTime();

                        deltaNano = (te - ts);
                        deltaSecond = deltaNano / SECONDS;
                        bps = ((double)msg.length) / deltaSecond;

                        if (bps > bpsMaxDec)
                        {
                            bpsMaxDec = bps;
                        }

                        accumulatorDec = bpsMaxDec;
//                        samples += 1;
                        msg[0] += 1;
                    }
//                    catch (Exception e)
//                    {
//                        e.printStackTrace();
//                    }

                }


//                dataPoints.add(new Sample("Encrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
//                dataPoints.add(new Sample("Decrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Encrypt " + ks + " ", msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Decrypt " + ks + " ", msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));


                if (msgSize < 2048)
                {
                    msgSize += 16;
                }
                else
                {
                    msgSize += 256;
                }
            }
        }


    }


    public static void benchmarkECB(int maxSize, List<Sample> dataPoints)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

//        for (int j = 0; j < 2; j++) {

        System.out.println();
        System.out.println();

        dataPoints.clear();
        int msgSize = 16;
        for (; msgSize < maxSize; )
        {
            byte[] msg = new byte[msgSize];
            Arrays.fill(msg, (byte)msgSize);

            int[] keySizes = new int[]{16, 24, 32};

            for (int ks : keySizes)
            {

                byte[] key = new byte[ks];
                random.nextBytes(key);


//                FipsAES.OperatorFactory fipsSymmetricFactory = new FipsAES.OperatorFactory();
//
//                FipsOutputEncryptor<FipsAES.Parameters> outputEncryptor = fipsSymmetricFactory.createOutputEncryptor(
//                        new SymmetricSecretKey(FipsAES.ECBwithPKCS7, key), FipsAES.ECBwithPKCS7);
//
//
//                FipsOutputDecryptor<FipsAES.Parameters> inputEncryptor = fipsSymmetricFactory.createOutputDecryptor(
//                        new SymmetricSecretKey(FipsAES.ECBwithPKCS7, key), FipsAES.ECBwithPKCS7);

                Cipher enc = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");


                Cipher dec = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");

                double accumulatorEnc = 0;
                double accumulatorDec = 0;
                double samples = 1;
                double maxEnc = Double.MIN_VALUE;
                double maxDec = maxEnc;
                ByteArrayOutputStream ct = new ByteArrayOutputStream(256 * 1024);
                ByteArrayOutputStream pt = new ByteArrayOutputStream(256 * 1024);

                for (int k = 0; k < 100; k++)
                {
                    try
                    {
                        ct.reset();
//                    OutputStream enc = outputEncryptor.getEncryptingStream(ct);
                        enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                        long ts = System.nanoTime();
                        byte[] c = enc.update(msg);
                        byte[] d = enc.doFinal();
                        long te = System.nanoTime();

                        double deltaNano = (te - ts);
                        double deltaSecond = deltaNano / SECONDS;
                        double bps = ((double)msg.length) / deltaSecond;

                        if (bps > maxEnc)
                        {
                            maxEnc = bps;
                        }

                        accumulatorEnc = maxEnc;
                        if (c != null)
                        {
                            ct.write(c);
                        }
                        ct.write(d);
                        pt.reset();
//                    OutputStream os = inputEncryptor.getDecryptingStream(pt);
                        dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
                        d = ct.toByteArray();
                        ts = System.nanoTime();
                        c = dec.update(d);
                        d = dec.doFinal();
//                    os.write(d);
//                    os.close();
                        te = System.nanoTime();
                        if (c != null)
                        {
                            pt.write(c);
                        }
                        if (d != null)
                        {
                            pt.write(d);
                        }
                        if (!MessageDigest.isEqual(pt.toByteArray(), msg))
                        {

                            System.out.println(Hex.toHexString(ct.toByteArray()) + " " + ct.toByteArray().length);

                            System.out.println();


                            System.out.println(Hex.toHexString(pt.toByteArray()));
                            System.out.println();
                            System.out.println(Hex.toHexString(msg));

                            System.out.println((pt.toByteArray().length - msg.length) / 16);
                            //throw new RuntimeException("ecb pt not equal");
                        }
                        deltaNano = (te - ts);
                        deltaSecond = deltaNano / SECONDS;
                        bps = ((double)msg.length) / deltaSecond;

                        if (bps > maxDec)
                        {
                            maxDec = bps;
                        }


                        accumulatorDec = maxDec;
//                        samples += 1;
                        msg[0] += 1;
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                    }
                }
                dataPoints.add(new Sample("Encrypt " + ks + " ", msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Decrypt " + ks + " ", msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));

//                dataPoints.add(new Sample("Encrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
//                dataPoints.add(new Sample("Decrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));

                if (msgSize < 2048)
                {
                    msgSize += 16;
                }
                else
                {
                    msgSize += 256;
                }
            }

        }

        // }


    }


    public static void benchmarkECBJCE(int maxSize, List<Sample> dataPoints)
        throws Exception
    {
        SecureRandom random = new SecureRandom();

//        for (int j = 0; j < 2; j++) {

        dataPoints.clear();
        int msgSize = 16;
        for (; msgSize < maxSize; )
        {
            byte[] msg = new byte[msgSize];
            Arrays.fill(msg, (byte)msgSize);

            byte[] cText = new byte[msgSize + 16];
            byte[] pText = new byte[msgSize + 16];

            int[] keySizes = new int[]{16, 24, 32};

            for (int ks : keySizes)
            {

                byte[] key = new byte[ks];
                random.nextBytes(key);


//                Cipher enc = Cipher.getInstance("AES/ECB/PKCS7Padding", BouncyCastleFipsProvider.PROVIDER_NAME);
//                enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
                Cipher enc = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
                enc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

                Cipher dec = Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
                dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));
//                Cipher dec = Cipher.getInstance("AES/ECB/PKCS7Padding", BouncyCastleFipsProvider.PROVIDER_NAME);
//                dec.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"));


                double accumulatorEnc = 0;
                double accumulatorDec = 0;
                double samples = 1;
                double maxEnc = Double.MIN_VALUE;
                double maxDec = maxEnc;


                for (int k = 0; k < 100; k++)
                {

                    int l = 0;

                    long ts = System.nanoTime();
                    l = enc.update(msg, 0, msg.length, cText);
                    enc.doFinal(cText, l);
                    long te = System.nanoTime();

                    double deltaNano = (te - ts);
                    double deltaSecond = deltaNano / SECONDS;
                    double bps = ((double)msg.length) / deltaSecond;

                    if (bps > maxEnc)
                    {
                        maxEnc = bps;
                    }

                    accumulatorEnc = maxEnc;


                    ts = System.nanoTime();
                    l = dec.update(cText, 0, cText.length, pText);
                    dec.doFinal(pText, l);
                    te = System.nanoTime();

                    if (!Arrays.areEqual(pText, 0, msg.length, msg, 0, msg.length))
                    {

                        System.out.println(Hex.toHexString(cText) + " " + cText.length);

                        System.out.println();


                        System.out.println(Hex.toHexString(pText));
                        System.out.println();
                        System.out.println(Hex.toHexString(msg));

                        System.out.println((pText.length - msg.length) / 16);
                        throw new RuntimeException("ecb pt not equal");
                    }
                    deltaNano = (te - ts);
                    deltaSecond = deltaNano / SECONDS;
                    bps = ((double)msg.length) / deltaSecond;

                    if (bps > maxDec)
                    {
                        maxDec = bps;
                    }


                    accumulatorDec = maxDec;
                    // samples += 1;
                    msg[0] += 1;
                }


                dataPoints.add(new Sample("Encrypt " + ks + " ", msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Decrypt " + ks + " ", msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));
//                dataPoints.add(new Sample("Encrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
//                dataPoints.add(new Sample("Decrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));

                if (msgSize < 2048)
                {
                    msgSize += 16;
                }
                else
                {
                    msgSize += 256;
                }
            }

        }

        // }


    }

    public static void benchmarkCFB(int maxSize, List<Sample> dataPoints)
        throws Exception
    {

        SecureRandom random = new SecureRandom();
        int msgSize = 1;
        ByteArrayOutputStream ct = new ByteArrayOutputStream(2048 * 1024);
        ByteArrayOutputStream pt = new ByteArrayOutputStream(2048 * 1024);
        for (; msgSize < maxSize; )
        {
            byte[] msg = new byte[msgSize];


            Arrays.fill(msg, (byte)msgSize);

            int[] keySizes = new int[]{16, 24, 32};

            for (int ks : keySizes)
            {
                byte[] key = new byte[ks];
                random.nextBytes(key);
                byte[] nonce = Hex.decode("58d2240f580a31c1d24948e900001111");
//                FipsAEADOperatorFactory<FipsAES.AuthParameters> fipsSymmetricFactory = new FipsAES.AEADOperatorFactory();
//                FipsOutputAEADEncryptor<Cipher.AuthParameters> outputEncryptor = fipsSymmetricFactory.createOutputAEADEncryptor(
//                        new SymmetricSecretKey(FipsAES.GCM, key), FipsAES.GCM.withMACSize(128).withIV(nonce));
//                FipsOutputAEADDecryptor<FipsAES.AuthParameters> inputEncryptor = fipsSymmetricFactory.createOutputAEADDecryptor(
//                        new SymmetricSecretKey(FipsAES.GCM, key), FipsAES.GCM.withMACSize(128).withIV(nonce));
                double accumulatorEnc = 0;
                double accumulatorDec = 0;
                double samples = 1;
                double bpsMaxEnc = Double.MIN_VALUE;
                double bpsMaxDec = Double.MIN_VALUE;
                Cipher enc = Cipher.getInstance("AES/CFB/NoPadding", "BC");
                for (int k = 0; k < 30; k++)
                {
                    ct.reset();
                    //OutputStream enc = outputEncryptor.getEncryptingStream(ct);
                    try
                    {

                        KeyGenerator kGen = KeyGenerator.getInstance("AES", "BC");
                        Key keys = kGen.generateKey();
                        enc.init(Cipher.ENCRYPT_MODE, keys, new IvParameterSpec(nonce));
                        long ts = System.nanoTime();
                        byte[] c = enc.update(msg);
                        byte[] d = enc.doFinal();
//                    enc.write(msg);
//                    enc.close();
                        long te = System.nanoTime();
                        if (c != null)
                        {
                            ct.write(c);
                        }

                        ct.write(d);
                        double deltaNano = (te - ts);
                        double deltaSecond = deltaNano / SECONDS;
                        double bps = ((double)msg.length) / deltaSecond;
                        if (bps > bpsMaxEnc)
                        {
                            bpsMaxEnc = bps;
                        }
                        accumulatorEnc = bpsMaxEnc;
                        pt.reset();
                        //OutputStream os = inputEncryptor.getDecryptingStream(pt);
                        enc.init(Cipher.DECRYPT_MODE, keys, new IvParameterSpec(nonce));
                        d = ct.toByteArray();
                        ts = System.nanoTime();
                        enc.update(d);
                        enc.doFinal();
//                    os.write(d);
//                    os.close();
                        te = System.nanoTime();
//                    if (!MessageDigest.isEqual(pt.toByteArray(), msg)) {
//                        throw new RuntimeException("gcm pt not equal");
//                    }
                        deltaNano = (te - ts);
                        deltaSecond = deltaNano / SECONDS;
                        bps = ((double)msg.length) / deltaSecond;
                        if (bps > bpsMaxDec)
                        {
                            bpsMaxDec = bps;
                        }
                        accumulatorDec = bpsMaxDec;
                        //   samples += 1;
                        msg[0] += 1;
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                    }


                }
//                dataPoints.add(new Sample("Encrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
//                dataPoints.add(new Sample("Decrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Encrypt " + ks + " ", msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Decrypt " + ks + " ", msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));


                if (msgSize < 128)
                {
                    msgSize += 1;
                }
                else if (msgSize < 2048)
                {
                    msgSize += 16;
                }
                else
                {
                    msgSize += 2048;
                }
            }
        }
    }

    public static void benchmarkCTR(int maxSize, List<Sample> dataPoints)
        throws Exception
    {

        SecureRandom random = new SecureRandom();
        int msgSize = 1;
        ByteArrayOutputStream ct = new ByteArrayOutputStream(2048 * 1024);
        ByteArrayOutputStream pt = new ByteArrayOutputStream(2048 * 1024);
        for (; msgSize < maxSize; )
        {
            byte[] msg = new byte[msgSize];


            Arrays.fill(msg, (byte)msgSize);

            int[] keySizes = new int[]{16, 24, 32};

            for (int ks : keySizes)
            {
                byte[] key = new byte[ks];
                random.nextBytes(key);
                byte[] nonce = Hex.decode("58d2240f580a31c1d24948e900001111");
//                FipsAEADOperatorFactory<FipsAES.AuthParameters> fipsSymmetricFactory = new FipsAES.AEADOperatorFactory();
//                FipsOutputAEADEncryptor<Cipher.AuthParameters> outputEncryptor = fipsSymmetricFactory.createOutputAEADEncryptor(
//                        new SymmetricSecretKey(FipsAES.GCM, key), FipsAES.GCM.withMACSize(128).withIV(nonce));
//                FipsOutputAEADDecryptor<FipsAES.AuthParameters> inputEncryptor = fipsSymmetricFactory.createOutputAEADDecryptor(
//                        new SymmetricSecretKey(FipsAES.GCM, key), FipsAES.GCM.withMACSize(128).withIV(nonce));
                double accumulatorEnc = 0;
                double accumulatorDec = 0;
                double samples = 1;
                double bpsMaxEnc = Double.MIN_VALUE;
                double bpsMaxDec = Double.MIN_VALUE;
                Cipher enc = Cipher.getInstance("AES/CTR/PKCS7Padding", "BC");
                for (int k = 0; k < 30; k++)
                {
                    ct.reset();
                    //OutputStream enc = outputEncryptor.getEncryptingStream(ct);
                    try
                    {

                        KeyGenerator kGen = KeyGenerator.getInstance("AES", "BC");
                        Key keys = kGen.generateKey();
                        enc.init(Cipher.ENCRYPT_MODE, keys, new IvParameterSpec(nonce));
                        long ts = System.nanoTime();
                        byte[] c = enc.update(msg);
                        byte[] d = enc.doFinal();
//                    enc.write(msg);
//                    enc.close();
                        long te = System.nanoTime();
                        if (c != null)
                        {
                            ct.write(c);
                        }

                        ct.write(d);
                        double deltaNano = (te - ts);
                        double deltaSecond = deltaNano / SECONDS;
                        double bps = ((double)msg.length) / deltaSecond;
                        if (bps > bpsMaxEnc)
                        {
                            bpsMaxEnc = bps;
                        }
                        accumulatorEnc = bpsMaxEnc;
                        pt.reset();
                        //OutputStream os = inputEncryptor.getDecryptingStream(pt);
                        enc.init(Cipher.DECRYPT_MODE, keys, new IvParameterSpec(nonce));
                        d = ct.toByteArray();
                        ts = System.nanoTime();
                        enc.update(d);
                        enc.doFinal();
//                    os.write(d);
//                    os.close();
                        te = System.nanoTime();
//                    if (!MessageDigest.isEqual(pt.toByteArray(), msg)) {
//                        throw new RuntimeException("gcm pt not equal");
//                    }
                        deltaNano = (te - ts);
                        deltaSecond = deltaNano / SECONDS;
                        bps = ((double)msg.length) / deltaSecond;
                        if (bps > bpsMaxDec)
                        {
                            bpsMaxDec = bps;
                        }
                        accumulatorDec = bpsMaxDec;
                        //   samples += 1;
                        msg[0] += 1;
                    }
                    catch (Exception e)
                    {
                        e.printStackTrace();
                    }


                }
//                dataPoints.add(new Sample("Encrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
//                dataPoints.add(new Sample("Decrypt " + ks + " " + FipsStatus.getNativeLibraryIdent(), msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Encrypt " + ks + " ", msg.length, (accumulatorEnc / samples) / 1024.0, "KB/s"));
                dataPoints.add(new Sample("Decrypt " + ks + " ", msg.length, (accumulatorDec / samples) / 1024.0, "KB/s"));


                if (msgSize < 128)
                {
                    msgSize += 1;
                }
                else if (msgSize < 2048)
                {
                    msgSize += 16;
                }
                else
                {
                    msgSize += 2048;
                }
            }
        }
    }


    public static class Sample
    {
        public final String label;
        public final long messageSize;
        public final double value;
        public final String unit;

        public Sample(String label, long messageSize, double value, String unit)
        {
            this.label = label;
            this.messageSize = messageSize;
            this.value = value;
            this.unit = unit;
        }

        public Sample(String line)
        {
            String[] parts = line.trim().split(",");
            this.label = parts[0].replace("\"", "");
            this.messageSize = Integer.parseInt(parts[1]);
            this.value = Double.parseDouble(parts[2]);
            this.unit = parts[3];
        }

        public String asCSV()
        {
            StringBuilder builder = new StringBuilder();
            builder.append('"');
            builder.append(label);
            builder.append("\"");
            builder.append(',');

            builder.append(messageSize);
            builder.append(",");
            builder.append(String.format("%.2f", value));
            builder.append(",");

            builder.append(unit);
            return builder.toString();
        }
    }

}
