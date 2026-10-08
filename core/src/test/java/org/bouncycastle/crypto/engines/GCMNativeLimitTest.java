package org.bouncycastle.crypto.engines;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class GCMNativeLimitTest extends TestCase
{
    @Before
    public void setUp()
    {
//        FipsStatus.isReady();
//        NativeLoader.setNativeEnabled(true);
    }

    static boolean skipIfNotSupported()
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/GCM"))
        {
            if (!System.getProperty("test.bclts.ignore.native","").contains("gcm"))
            {
                fail("no native gcm and no skip set for it");
                return false;
            }
            System.out.println("Skipping GCM native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return true;
        }
        return false;
    }


    @Test
    public void testGCMInitParamWithIV()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        //-- native

        new AESNativeGCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 31);
                    dispose(ref);
                    fail("incorrect mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid value for MAC"));
                }
                dispose(ref);
            }

        };


        new AESNativeGCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[11], null, 32);
                    dispose(ref);
                    fail("incorrect mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("IV must be at least 12 byte"));
                }
                dispose(ref);
            }

        };

    }


    @Test
    public void testGCMInitParamWithIV_1()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }


        new AESNativeGCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[15], new byte[10], null, 128);
                    dispose(ref);
                    fail("incorrect key size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("key must be only 16, 24 or 32 bytes long"));
                }
                dispose(ref);
            }

        };

    }

    @Test
    public void testGCMInitParamWithIV_2()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], null, null, 128);
                    dispose(ref);
                    fail("null iv");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("iv was null"));
                }
                dispose(ref);
            }

        };

    }


    @Test
    public void testGCMInitParamWithIV_3()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }
        //


        new AESNativeGCM()
        {
            {
                //
                // Passing null iv causes some failure.
                //
                try
                {
                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[0])
                    {
                        @Override
                        public byte[] getIV()
                        {
                            return null;
                        }
                    };
                    init(true, piv);
                    fail("accepted null iv");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("IV must be at least 12 byte"));
                }
            }
        };

    }

    @Test
    public void testGCMInitParamWithIV_4()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }


        new AESNativeGCM()
        {
            {
                //
                // Passing null key causes some failure
                //
                try
                {
                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[0])
                    {
                        @Override
                        public byte[] getKey()
                        {
                            return null;
                        }
                    }, new byte[1]);
                    init(true, piv);
                    fail("accepted null key");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("IV must be at least 12 byte"));
                }
            }
        };

    }

    @Test
    public void testGCMInitParamWithIV_5()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {

                //
                // Pass invalid iv size
                //
                try
                {
                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[0]);
                    init(true, piv);
                    fail("accepted invalid iv size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("IV must be at least 12 byte"));
                }
            }
        };

    }

    @Test
    public void testGCMInitParamWithIV_6()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                //
                // Pass invalid key size
                //
                try
                {
                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[15]), new byte[16]);
                    init(true, piv);
                    fail("accepted invalid key size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("key must be only"));
                }
            }
        };

    }

    @Test
    public void testGCMInitParamWithIV_7()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                // Wrong param type.
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    fail("accepted invalid parameters");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid parameters"));
                }
            }
        };

    }

    @Test
    public void testGCMInitParamWithIV_8()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                // Null params/
                try
                {
                    init(true, null);
                    fail("accepted invalid parameters");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid parameters"));
                }
            }
        };

    }

    @Test
    public void testGCMInitParamWithIV_9()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {

                //
                // Key changing
                //

                ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]);
                init(true, piv);
                try
                {
                    init(true, new ParametersWithIV(null, new byte[16]));
                    fail("nonce reuse encryption");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("cannot reuse nonce for GCM encryption"));
                }

                try
                {
                    init(true, piv);
                    fail("nonce reuse encryption");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("cannot reuse nonce for GCM encryption"));
                }
                piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]);
                init(false, piv);
            }

        };
    }

    @Test
    public void testGCMInitAEADParams()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                //
                // Passing null iv causes some failure.
                //
                try
                {
                    AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[0])
                    {

                        @Override
                        public byte[] getNonce()
                        {
                            return null;
                        }
                    };
                    init(true, piv);
                    fail("accepted null iv");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("IV must be at least 12 bytes"));
                }


                //
                // Passing null key causes some failure
                //
                try
                {
                    AEADParameters piv = new AEADParameters(new KeyParameter(new byte[0])
                    {
                        @Override
                        public byte[] getKey()
                        {
                            return null;
                        }
                    }, 128, new byte[1]);
                    init(true, piv);
                    fail("accepted null key");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("IV must be at least 12 byte"));
                }

                //
                // Null associated text is valid.
                //
                {
                    AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12], null);
                    init(true, piv);
                }


                //
                // Pass invalid iv size
                //
                try
                {
                    AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[0]);
                    init(true, piv);
                    fail("accepted invalid iv size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("IV must be at least 12 byte"));
                }

                //
                // Pass invalid key size
                //
                try
                {
                    AEADParameters piv = new AEADParameters(new KeyParameter(new byte[15]), 128, new byte[16]);
                    init(true, piv);
                    fail("accepted invalid key size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("key must be only"));
                }

                // Wrong param type.
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    fail("accepted invalid parameters");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid parameters"));
                }

                // Null params/
                try
                {
                    init(true, null);
                    fail("accepted invalid parameters");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid parameters"));
                }


                //
                // Key changing
                //


                AEADParameters piv = new AEADParameters(new KeyParameter(Hex.decode("01000000000000000000000000000000")), 128, new byte[16]);
                init(true, piv);
                try
                {
                    init(true, new AEADParameters(null, 128, new byte[16]));
                    fail("nonce reuse encryption");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("cannot reuse nonce for GCM encryption"));
                }

                try
                {
                    init(true, piv);
                    fail("nonce reuse encryption");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("cannot reuse nonce for GCM encryption"));
                }

                // Should pass.
                piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[16]);
                init(false, piv);

                try
                {
                    init(true, new AEADParameters(null, 127, new byte[16]));
                    fail("invalid mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid value for MAC size"));
                }

                try
                {
                    init(true, new AEADParameters(null, 16, new byte[16]));
                    fail("invalid mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid value for MAC size"));
                }

                try
                {
                    init(true, new AEADParameters(null, 129, new byte[16]));
                    fail("invalid mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid value for MAC size"));
                }


            }

        };
    }

    @Test
    public void testGCMAADBytes()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
        new AESNativeGCM()
        {
            {
                init(true, piv);

                // Null aad array
                try
                {
                    processAADBytes(null, 0, 0);
                    fail("null aad array");
                }
                catch (Exception ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }

                // negative inOff
                try
                {
                    processAADBytes(new byte[0], -1, 0);
                    fail("negative aad offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("offset is negative"));
                }

                // negative len
                try
                {
                    processAADBytes(new byte[0], 0, -1);
                    fail("negative aad len");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("len is negative"));
                }

                try
                {
                    processAADBytes(new byte[10], 1, 10);
                    fail("len + offset too long");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("array too short for offset + len"));
                }

                try
                {
                    processAADBytes(new byte[10], 0, 11);
                    fail("len too long");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("array too short for offset + len"));
                }
            }
        };

        new AESNativeGCM()
        {
            {
                try
                {
                    processAADBytes(new byte[10], 0, 10);
                    fail("unitialised GCM");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("GCM is uninitialized"));
                }

            }
        };
    }

    @Test
    public void testGCMProcessByte1() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
        new AESNativeGCM()
        {

            {
                init(true, piv);

                // Null out array
                try
                {
                    processByte(b, null, 0);
                }
                catch (Exception ex)
                {
                    fail("did not accept null output array");
                }

            }
        };

    }

    @Test
    public void testGCMProcessByte2() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);

        new AESNativeGCM()
        {
            {
                // negative outOff
                try
                {
                    init(true, piv);
                    processByte(b, new byte[0], -1);
                    fail("negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("offset is negative"));
                }

            }
        };

    }

    @Test
    public void testGCMProcessByte3() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
        new AESNativeGCM()
        {
            {

                try
                {
                    init(true, piv);
                    processByte(b, new byte[0], 1);
                    fail("offset past end of array");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("offset past end"));
                }

            }
        };

    }

    @Test
    public void testGCMProcessByte4() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);

        new AESNativeGCM()
        {
            {
                try
                {
                    init(true, piv);
                    processByte(b, null, 20);

                }
                catch (Exception ex)
                {
                    fail("failed to accept null output array");
                }

            }
        };

    }

    @Test
    public void testGCMProcessByte5() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
        new AESNativeGCM()
        {
            {

                try
                {
                    processByte(b, new byte[10], 10);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("uninitialized"));
                }

            }
        };


    }

    @Test
    public void testGCMProcessByte6() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }



        {
            // attempt to cause write past end of buffer.

            byte[] in = new byte[1024];
            byte[] out = new byte[1023];

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

            int l = 0;

            l = nativeGCM.processBytes(in, 0, in.length - 1, out, 0);

            try
            {
                l = nativeGCM.processBytes(in, l, 1, out, l);
                fail("must through output length exception");
            }
            catch (Exception ex)
            {
                assertTrue(ex.getMessage().contains("output len too short"));
            }

        }

    }


    @Test
    public void testGCMProcessBytes7()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);

        new AESNativeGCM()
        {
            {
                init(true, piv);


                //
                // Null input array
                //
                try
                {
                    processBytes(null, 0, 1, new byte[16], 0);
                    fail("accepted null input array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                    TestCase.assertTrue(ex.getMessage().contains("input was null"));
                }




                //
                // Negative input offset.
                //
                try
                {
                    processBytes(new byte[0], -1, 1, new byte[0], 0);
                    fail("accepted negative in offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("offset is negative"));
                }

                //
                // Negative block count.
                //
                try
                {
                    processBytes(new byte[0], 0, -1, new byte[0], 0);
                    fail("accepted negative block count ");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("len is negative"));
                }

                //
                // Negative output offset
                //
                try
                {
                    processBytes(new byte[1], 0, 1, new byte[0], -1);
                    fail("accepted negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("offset is negative"));
                }

                //
                // Input len +len > in array length
                //
                try
                {
                    processBytes(new byte[10], 1, 10, new byte[0], 0);
                    fail("in offset + len > in len");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("array too short for offset + len"));
                }


            }
        };
        new AESNativeGCM()
        {
            {
                //
                // Valid inputs but not initialised.
                //
                try
                {
                    processBytes(new byte[16], 0, 1, new byte[16], 0);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("uninitialized"));
                }


            }

        };
    }

    /**
     * Test GCM with combinations of zero length output and null output arrays.
     * This can be valid input especially when the caller has erroneously determined they
     * do not expect to get any output.
     *
     * @throws Exception
     */
    @Test
    public void testGCMOutputVariations()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        { // Zero length output array
            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in = new byte[32];
            byte[] out = new byte[0];

            // Passes because 32 bytes will not trigger any output.
            nativeGCM.processBytes(in, 0, in.length, out, 0);
        }


        { // nonzero output array but offset at end.
            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in = new byte[32];
            byte[] out = new byte[32];

            // Passes because 32 bytes will not trigger any output.
            nativeGCM.processBytes(in, 0, in.length, out, 32);
        }

        { // null output array
            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in = new byte[32];
            byte[] out = null;

            // Passes because 32 bytes will not trigger any output.
            nativeGCM.processBytes(in, 0, in.length, out, 0);
        }

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        try
        { // zero length output array but output generated

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in;
            if (nativeServices.getLibraryIdent().contains("vaesf"))
            {
                in = new byte[513];
            }
            else if (nativeServices.getLibraryIdent().contains("vaes"))
            {
                in = new byte[129];
            }
            else
            {
                in = new byte[65];
            }

            byte[] out = new byte[0];

            nativeGCM.processBytes(in, 0, in.length, out, 0);
            fail("zero len but output");
        }
        catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("output len too short"));
        }


        try
        { // null output non zero offset.

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in;
            if (nativeServices.getLibraryIdent().contains("vaesf"))
            {
                in = new byte[513];
            }
            else if (nativeServices.getLibraryIdent().contains("vaes"))
            {
                in = new byte[129];
            }
            else
            {
                in = new byte[65];
            }


            nativeGCM.processBytes(in, 0, in.length, null, 20);
            fail("null array output offset");
        }
        catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("output len too short"));
        }


        try
        { // zero len output, positive offset

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in;
            if (nativeServices.getLibraryIdent().contains("vaesf"))
            {
                in = new byte[513];
            }
            else if (nativeServices.getLibraryIdent().contains("vaes"))
            {
                in = new byte[129];
            }
            else
            {
                in = new byte[65];
            }

            nativeGCM.processBytes(in, 0, in.length, new byte[0], 20);
            fail("zero len but output");
        }
        catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("offset past end of array"));
        }


        try
        { // null output array but output generated

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in;
            if (nativeServices.getLibraryIdent().contains("vaesf"))
            {
                in = new byte[513];
            }
            else if (nativeServices.getLibraryIdent().contains("vaes"))
            {
                in = new byte[129];
            }
            else
            {
                in = new byte[65];
            }
            byte[] out = null;

            // Passes because 32 bytes will not trigger any output.
            nativeGCM.processBytes(in, 0, in.length, out, 0);
            fail("null output");
        }
        catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("output len too short"));
        }

        try
        { // long enough output array but offset at array.len

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in;
            if (nativeServices.getLibraryIdent().contains("vaesf"))
            {
                in = new byte[513];
            }
            else if (nativeServices.getLibraryIdent().contains("vaes"))
            {
                in = new byte[129];
            }
            else
            {
                in = new byte[65];
            }
            byte[] out = new byte[65];

            // Passes because 32 bytes will not trigger any output.
            nativeGCM.processBytes(in, 0, in.length, out, 65);
            fail("not enough output");
        }
        catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("output len too short"));
        }

        try
        { // long enough output array but offset in the middle

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in;
            if (nativeServices.getLibraryIdent().contains("vaesf"))
            {
                in = new byte[513];
            }
            else if (nativeServices.getLibraryIdent().contains("vaes"))
            {
                in = new byte[129];
            }
            else
            {
                in = new byte[65];
            }
            byte[] out = new byte[65];

            // Passes because 32 bytes will not trigger any output.
            nativeGCM.processBytes(in, 0, in.length, out, 32);
            fail("not enough output");
        }
        catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("output len too short"));
        }


        {
            // Long enough input to cause loop in native processBytes but output buffer to short after
            // initial iterations.

            byte[] in = new byte[1024];
            byte[] out = new byte[1023];

            AESNativeGCM nativeGCM = new AESNativeGCM();
            nativeGCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

            try
            {
                nativeGCM.processBytes(in, 0, in.length, out, 0);
                fail("must through output length exception");
            }
            catch (Exception ex)
            {
                assertTrue(ex.getMessage().contains("output len too short"));
            }

        }

    }

    @Test
    public void testGCMDoFinal_1()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }


        new AESNativeGCM()
        {
            {
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    doFinal(null, 0);
                    fail("negative output offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                    assertTrue(ex.getMessage().contains("output was null"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_2()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    doFinal(new byte[16], -1);
                    fail("negative output offset");
                }
                catch (Exception ex)
                {
                    ex.getMessage().contains("is negative");
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_3()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    doFinal(new byte[16], 17);
                    fail("offset past end of buffer");
                }
                catch (Exception ex)
                {
                    ex.getMessage().contains("offset past end of buffer");
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_4()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                {
                    doFinal(new byte[16], 0);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("needs to be initialised"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_5()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                {
                    try
                    {
                        init(true, null);
                    }
                    catch (Exception ignored)
                    {
                    }
                    ;

                    doFinal(new byte[16], 0);
                    fail("cannot be reused");
                }
                catch (Exception ex)
                {
                    ex.getMessage().contains("cannot be reused");
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_6()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[0];
                    byte[] out = new byte[15];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_7()
            throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[16];
                    byte[] out = new byte[16 + 15];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_8()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[32];
                    byte[] out = new byte[32 + 15];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_9()
            throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[48];
                    byte[] out = new byte[48 + 15];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_10()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[64];
                    byte[] out = new byte[64 + 15];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_12()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[96];
                    byte[] out = new byte[96 + 15];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_13()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[16 + 16];
                    byte[] out = new byte[15]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_14()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[33 + 16];
                    byte[] out = new byte[32]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_15()
            throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[49 + 16];
                    byte[] out = new byte[48]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_16()
            throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[65 + 16];
                    byte[] out = new byte[64]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_17()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeGCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[96 + 16];
                    byte[] out = new byte[95]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };

    }

    @Test
    public void testGCMDoFinal_18()
            throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeGCM()
        {
            { // Verify output length verification failure from native side on encryption.
                try
                { // One byte too short for final with message 128b mac
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] in = new byte[1024 + 15]; // One byte too small to hold tag
                    byte[] out = new byte[1024]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too small"));
                }
            }
        };


    }

    @Test
    public void testGCMDoFinal_19()
            throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }
        //
        // Generate a valid cipher text, tag etc.
        //
        AESNativeGCM gcm = new AESNativeGCM();
        gcm.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        byte[] validResult = new byte[1024 + 16];
        int l = gcm.processBytes(new byte[1024], 0, 1024, validResult, 0);
        gcm.doFinal(validResult, l);
        gcm.reset();

        new AESNativeGCM()
        {
            {
                //
                // Verify invalid cipher text when internal buffer is less than tag len on call to doFinal
                // in decryption.
                //
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    byte[] out = new byte[1024]; // Too small output by one.
                    int l = processBytes(validResult, 0, 15, out, 0);
                    doFinal(out, l);
                    fail("too short cipher text");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("cipher text too short"));
                }
            }
        };


        {


            new AESNativeGCM()
            {
                { // Verify there is enough output buffer to hold decryption result on doFinal
                    try
                    { // One byte too short for final with message 128b mac
                        init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                        byte[] out = new byte[1024]; // Too small output by one.
                        int l = processBytes(validResult, 0, validResult.length - 1, out, 0);
                        doFinal(new byte[15], 0);
                        fail("too short cipher text");
                    }
                    catch (Exception ex)
                    {
                        assertTrue(ex.getMessage().contains("output buffer too small"));
                    }
                }
            };


        }


    }


    /**
     * Every method on a never-initialised native GCM must behave as GCMBlockCipher does,
     * not throw a NullPointerException off the missing native reference.
     */
    @Test
    public void testGCMBeforeInit()
        throws Exception
    {
        if (skipIfNotSupported())
        {
            return;
        }

        int[] lens = { 0, 1, 15, 16, 17, 31, 32, 33, 1024, -1, -16, Integer.MIN_VALUE, Integer.MAX_VALUE };
        for (int i = 0; i != lens.length; i++)
        {
            GCMModeCipher java = new GCMBlockCipher(new AESEngine());
            AESNativeGCM nat = new AESNativeGCM();

            assertEquals("getOutputSize(" + lens[i] + ")", java.getOutputSize(lens[i]), nat.getOutputSize(lens[i]));
            assertEquals("getUpdateOutputSize(" + lens[i] + ")", java.getUpdateOutputSize(lens[i]), nat.getUpdateOutputSize(lens[i]));
        }

        AESNativeGCM nat = new AESNativeGCM();
        assertTrue(Arrays.areEqual(new GCMBlockCipher(new AESEngine()).getMac(), nat.getMac()));
        assertEquals(0, nat.getMac().length);

        try
        {
            nat.processAADByte((byte)0);
            fail("processAADByte before init");
        }
        catch (IllegalStateException e)
        {
            assertEquals("GCM is uninitialized", e.getMessage());
        }

        try
        {
            nat.doFinal(new byte[16], 0);
            fail("doFinal before init");
        }
        catch (IllegalStateException e)
        {
            assertEquals("GCM cipher needs to be initialised", e.getMessage());
        }

        // the guards must not stick once the cipher has been initialised.
        nat.init(true, new AEADParameters(new KeyParameter(new byte[16]), 96, new byte[12]));
        assertEquals(17 + 12, nat.getOutputSize(17));
        // native may buffer more than GCMBlockCipher (see README), but never reports more than it could write.
        int updateSize = nat.getUpdateOutputSize(17);
        assertTrue(updateSize >= 0 && updateSize <= 16 && updateSize % 16 == 0);
        nat.processAADByte((byte)1);
        byte[] out = new byte[12];
        assertEquals(12, nat.doFinal(out, 0));
        assertTrue(Arrays.areEqual(out, nat.getMac()));
        assertFalse(Arrays.areEqual(new byte[12], nat.getMac()));
    }

    /**
     * A null key in the parameters reuses the key from the previous init, as GCMBlockCipher does.
     */
    @Test
    public void testGCMKeyReuse()
        throws Exception
    {
        if (skipIfNotSupported())
        {
            return;
        }

        // no previous key - rejected as for GCMBlockCipher.
        for (int forEnc = 0; forEnc != 2; forEnc++)
        {
            CipherParameters[] cases = {
                new ParametersWithIV(null, new byte[12]),
                new AEADParameters(null, 128, new byte[12]) };
            for (int i = 0; i != cases.length; i++)
            {
                try
                {
                    new GCMBlockCipher(new AESEngine()).init(forEnc == 1, cases[i]);
                    fail("java: no key");
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals("Key must be specified in initial init", e.getMessage());
                }

                try
                {
                    new AESNativeGCM().init(forEnc == 1, cases[i]);
                    fail("native: no key");
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals("Key must be specified in initial init", e.getMessage());
                }
            }
        }

        // inner parameters that aren't a key - rejected as for GCMBlockCipher.
        CipherParameters notAKey = new ParametersWithIV(new ParametersWithIV(null, new byte[12]), new byte[12]);
        try
        {
            new GCMBlockCipher(new AESEngine()).init(true, notAKey);
            fail("java: not a key");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("invalid parameters passed to GCM", e.getMessage());
        }
        try
        {
            new AESNativeGCM().init(true, notAKey);
            fail("native: not a key");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("invalid parameters passed to GCM", e.getMessage());
        }

        long seed = new SecureRandom().nextLong();
        SecureRandom rand = new SecureRandom();
        rand.setSeed(seed);

        int[] keySizes = { 16, 24, 32 };
        for (int t = 0; t != 30; t++)
        {
            String msg = "seed " + seed + " iteration " + t;

            byte[] key = new byte[keySizes[t % 3]];
            byte[] otherKey = new byte[key.length];
            byte[] iv1 = new byte[12 + rand.nextInt(5)];
            byte[] iv2 = new byte[12 + rand.nextInt(5)];
            byte[] aad = new byte[rand.nextInt(40)];
            byte[] pt = new byte[rand.nextInt(100)];
            rand.nextBytes(key);
            rand.nextBytes(otherKey);
            rand.nextBytes(iv1);
            rand.nextBytes(iv2);
            iv2[0] = (byte)(iv1[0] ^ 1);
            rand.nextBytes(aad);
            rand.nextBytes(pt);
            otherKey[0] = (byte)(key[0] ^ 1);

            byte[] expected = gcm(new GCMBlockCipher(new AESEngine()), true,
                new AEADParameters(new KeyParameter(key), 128, iv2, aad), pt);

            // native: first init with the key, then reuse it with a new nonce.
            AESNativeGCM enc = new AESNativeGCM();
            byte[] ct1 = gcm(enc, true, new AEADParameters(new KeyParameter(key), 128, iv1, aad), pt);
            byte[] ct = gcm(enc, true, new AEADParameters(null, 128, iv2, aad), pt);
            assertTrue(msg, Arrays.areEqual(expected, ct));

            // the reused key really is the previous one, not some default.
            byte[] otherCt = gcm(new AESNativeGCM(), true,
                new AEADParameters(new KeyParameter(otherKey), 128, iv2, aad), pt);
            assertFalse(msg, Arrays.areEqual(ct, otherCt));

            // nonce reuse is still caught when the key is reused.
            try
            {
                enc.init(true, new AEADParameters(null, 128, iv2, aad));
                fail(msg + ": nonce reuse");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("cannot reuse nonce for GCM encryption", e.getMessage());
            }

            // decryption: first init with a different nonce, then reuse the key.
            AESNativeGCM dec = new AESNativeGCM();
            assertTrue(msg, Arrays.areEqual(pt, gcm(dec, false, new AEADParameters(new KeyParameter(key), 128, iv1, aad), ct1)));
            assertTrue(msg, Arrays.areEqual(pt, gcm(dec, false, new AEADParameters(null, 128, iv2, aad), ct)));

            byte[] bad = Arrays.clone(ct);
            bad[rand.nextInt(bad.length)] ^= (byte)(1 << rand.nextInt(8));
            try
            {
                gcm(dec, false, new AEADParameters(null, 128, iv2, aad), bad);
                fail(msg + ": tampered ciphertext accepted");
            }
            catch (InvalidCipherTextException e)
            {
                // expected
            }
        }
    }

    private static byte[] gcm(GCMModeCipher cipher, boolean forEncryption, AEADParameters params, byte[] in)
        throws InvalidCipherTextException
    {
        cipher.init(forEncryption, params);
        byte[] out = new byte[cipher.getOutputSize(in.length)];
        int len = cipher.processBytes(in, 0, in.length, out, 0);
        len += cipher.doFinal(out, len);
        return Arrays.copyOfRange(out, 0, len);
    }
}
