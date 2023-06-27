package org.bouncycastle.crypto.engines;

import java.security.Security;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class CCMNativeLimitTest
    extends TestCase
{
    public static void main(
        String[]    args)
        throws Exception
    {
//        Security.addProvider(new BouncyCastleProvider());

        CCMNativeLimitTest test=new CCMNativeLimitTest();
        test.testCCMInitParamWithIV();
        test.testCCMInitParamWithIV_1();
        test.testCCMInitParamWithIV_2();
        test.testCCMInitParamWithIV_3();
        test.testCCMInitParamWithIV_4();
        test.testCCMInitParamWithIV_5();
        test.testCCMInitParamWithIV_6();
        test.testCCMInitParamWithIV_7();
        test.testCCMInitParamWithIV_8();
//        test.testCCMInitParamWithIV_9();
        test.testCCMInitAEADParams();
        test.testCCMAADBytes();
        test.testCCMProcessByte1();
        test.testCCMProcessByte2();
        test.testCCMProcessByte3();
        test.testCCMProcessByte4();
        test.testCCMProcessByte5();
        test.testCCMProcessByte6();
        test.testCCMProcessBytes7();
        test.testCCMOutputVariations();
        test.testCCMDoFinal_1();
        test.testCCMDoFinal_2();
        test.testCCMDoFinal_3();
        test.testCCMDoFinal_4();
        test.testCCMDoFinal_5();
        test.testCCMDoFinal_6();
        test.testCCMDoFinal_7();
        test.testCCMDoFinal_8();
        test.testCCMDoFinal_9();
        test.testCCMDoFinal_10();
        test.testCCMDoFinal_12();
        test.testCCMDoFinal_13();
        test.testCCMDoFinal_14();
        test.testCCMDoFinal_15();
        test.testCCMDoFinal_16();
        test.testCCMDoFinal_17();
        test.testCCMDoFinal_18();
        test.testCCMDoFinal_19();

    }
    @Before
    public void setUp()
    {
//        FipsStatus.isReady();
//        NativeLoader.setNativeEnabled(true);
    }

    static boolean skipIfNotSupported()
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CCM"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("ccm"))
            {
                fail("no native ccm and no skip set for it");
                return false;
            }
            System.out.println("Skipping CFB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return true;
        }
        return false;
    }


    @Test
    public void testCCMInitParamWithIV()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        //-- native

        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0,31);
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


        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[14], null, 0,32);
                    dispose(ref);
                    fail("incorrect mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("nonce must have length from 7 to 13 octets"));
                }
                dispose(ref);
            }

        };

    }


    @Test
    public void testCCMInitParamWithIV_1()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }


        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[15], new byte[10], null, 0,128);
                    dispose(ref);
                    fail("incorrect key size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("key must be only 16,24 or 32 bytes long"));
                }
                dispose(ref);
            }

        };

    }

    @Test
    public void testCCMInitParamWithIV_2()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], null, null, 0,128);
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
    public void testCCMInitParamWithIV_3()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }
        //


        new AESNativeCCM()
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
                    assertTrue(ex.getMessage().contains("iv was null"));
                }
            }
        };

    }

    @Test
    public void testCCMInitParamWithIV_4()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }


        new AESNativeCCM()
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
                    assertTrue(ex.getMessage().contains("key was null"));
                }
            }
        };

    }

    @Test
    public void testCCMInitParamWithIV_5()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
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
                    assertTrue(ex.getMessage().contains("nonce must have length from 7 to 13 octets"));
                }
            }
        };

    }

    @Test
    public void testCCMInitParamWithIV_6()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
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
                    assertTrue(ex.getMessage().contains("key must be only 16,24 or 32 bytes long"));
                }
            }
        };

    }

    @Test
    public void testCCMInitParamWithIV_7()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
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
    public void testCCMInitParamWithIV_8()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
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

//    @Test
//    public void testCCMInitParamWithIV_9()
//        throws Exception
//    {
//
//        if (skipIfNotSupported())
//        {
//            return;
//        }
//
//        new AESNativeCCM()
//        {
//            {
//
//                //
//                // Key changing
//                //
//
//                ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]);
//                init(true, piv);
//                try
//                {
//                    init(true, new ParametersWithIV(null, new byte[12]));
//                    fail("nonce reuse encryption");
//                }
//                catch (Exception ex)
//                {
//                    assertTrue(ex.getMessage().contains("cannot reuse nonce for CCM encryption"));
//                }
//
////                try
////                {
////                    init(true, piv);
////                    fail("nonce reuse encryption");
////                }
////                catch (Exception ex)
////                {
////                    assertTrue(ex.getMessage().contains("cannot reuse nonce for CCM encryption"));
////                }
//                piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]);
//                init(false, piv);
//            }
//
//        };
//    }

    @Test
    public void testCCMInitAEADParams()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
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
                    assertTrue(ex.getMessage().contains("iv was null"));
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
                    assertTrue(ex.getMessage().contains("key was null"));
                }

                //
                // Null associated text is valid.
                //
                {
                    AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[13], null);
                    init(true, piv);
                }


                //
                // Pass invalid iv size
                //
                try
                {
                    reset();
                    AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[0]);
                    init(true, piv);
                    fail("accepted invalid iv size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("nonce must have length from 7 to 13 octets"));
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

                AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[13]);
                init(true, piv);
//                try
//                {
//                    init(true, new AEADParameters(null, 128, new byte[13]));
//                    fail("nonce reuse encryption");
//                }
//                catch (Exception ex)
//                {
//                    assertTrue(ex.getMessage().contains("cannot reuse nonce for CCM encryption"));
//                }

//                try
//                {
//                    init(true, piv);
//                    fail("nonce reuse encryption");
//                }
//                catch (Exception ex)
//                {
//                    assertTrue(ex.getMessage().contains("cannot reuse nonce for CCM encryption"));
//                }

                // Should pass.
                piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[13]);
                init(false, piv);

                try
                {
                    init(true, new AEADParameters(null, 127, new byte[13]));
                    fail("invalid mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid value for MAC size"));
                }

                try
                {
                    reset();
                    init(true, new AEADParameters(null, 16, new byte[13]));
                    fail("invalid mac size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid value for MAC size"));
                }

                try
                {
                    init(true, new AEADParameters(null, 129, new byte[13]));
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
    public void testCCMAADBytes()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
        new AESNativeCCM()
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

//        new AESNativeCCM()
//        {
//            {
//                try
//                {
//                    processAADBytes(new byte[10], 0, 10);
//                    fail("unitialised CCM");
//                }
//                catch (Exception ex)
//                {
//                    assertTrue(ex.getMessage().contains("CCM is uninitialized"));
//                }
//
//            }
//        };
    }

    @Test
    public void testCCMProcessByte1() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
        new AESNativeCCM()
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
    public void testCCMProcessByte2() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);

        new AESNativeCCM()
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
    public void testCCMProcessByte3() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
        new AESNativeCCM()
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
    public void testCCMProcessByte4() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        byte b = (byte) 1;

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);

        new AESNativeCCM()
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
    public void testCCMProcessByte5() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

//        byte b = (byte) 1;

//        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);
//        new AESNativeCCM()
//        {
//            {
//
//                try
//                {
//                    processByte(b, new byte[10], 10);
//                    fail("not initialized");
//                }
//                catch (Exception ex)
//                {
//                    assertTrue(ex.getMessage().contains("uninitialized"));
//                }
//
//            }
//        };


    }

    @Test
    public void testCCMProcessByte6() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }



//        {
//            // attempt to cause write past end of buffer.
//
//            byte[] in = new byte[1024];
//            byte[] out = new byte[1023];
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//
//            int l = 0;
//
//            l = nativeCCM.processBytes(in, 0, in.length - 1, out, 0);
//
//            try
//            {
//                l = nativeCCM.processBytes(in, l, 1, out, l);
//                fail("must through output length exception");
//            }
//            catch (Exception ex)
//            {
//                assertTrue(ex.getMessage().contains("output len too short"));
//            }
//
//        }

    }


    @Test
    public void testCCMProcessBytes7()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        AEADParameters piv = new AEADParameters(new KeyParameter(new byte[16]), 128, new byte[12]);

        new AESNativeCCM()
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
//        new AESNativeCCM()
//        {
//            {
//                //
//                // Valid inputs but not initialised.
//                //
//                try
//                {
//                    processBytes(new byte[16], 0, 1, new byte[16], 0);
//                    fail("not initialized");
//                }
//                catch (Exception ex)
//                {
//                    assertTrue(ex.getMessage().contains("uninitialized"));
//                }
//
//
//            }
//
//        };
    }

    /**
     * Test CCM with combinations of zero length output and null output arrays.
     * This can be valid input especially when the caller has erroneously determined they
     * do not expect to get any output.
     *
     * @throws Exception
     */
    @Test
    public void testCCMOutputVariations()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        { // Zero length output array
            AESNativeCCM nativeCCM = new AESNativeCCM();
            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
            byte[] in = new byte[32];
            byte[] out = new byte[0];

            // Passes because 32 bytes will not trigger any output.
            nativeCCM.processBytes(in, 0, in.length, out, 0);
        }


        { // nonzero output array but offset at end.
            AESNativeCCM nativeCCM = new AESNativeCCM();
            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
            byte[] in = new byte[32];
            byte[] out = new byte[32];

            // Passes because 32 bytes will not trigger any output.
            nativeCCM.processBytes(in, 0, in.length, out, 32);
        }

        { // null output array
            AESNativeCCM nativeCCM = new AESNativeCCM();
            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
            byte[] in = new byte[32];
            byte[] out = null;

            // Passes because 32 bytes will not trigger any output.
            nativeCCM.processBytes(in, 0, in.length, out, 0);
        }

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
//        try
//        { // zero length output array but output generated
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//            byte[] in;
//            if (nativeServices.getLibraryIdent().contains("vaesf"))
//            {
//                in = new byte[513];
//            }
//            else if (nativeServices.getLibraryIdent().contains("vaes"))
//            {
//                in = new byte[129];
//            }
//            else
//            {
//                in = new byte[65];
//            }
//
//            byte[] out = new byte[0];
//
//            nativeCCM.processBytes(in, 0, in.length, out, 0);
//            fail("zero len but output");
//        }
//        catch (Exception ex)
//        {
//            assertTrue(ex.getMessage().contains("output len too short"));
//        }


//        try
//        { // null output non zero offset.
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//            byte[] in;
//            if (nativeServices.getLibraryIdent().contains("vaesf"))
//            {
//                in = new byte[513];
//            }
//            else if (nativeServices.getLibraryIdent().contains("vaes"))
//            {
//                in = new byte[129];
//            }
//            else
//            {
//                in = new byte[65];
//            }
//
//
//            nativeCCM.processBytes(in, 0, in.length, null, 20);
//            fail("null array output offset");
//        }
//        catch (Exception ex)
//        {
//            assertTrue(ex.getMessage().contains("output len too short"));
//        }


//        try
//        { // zero len output, positive offset
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//            byte[] in;
//            if (nativeServices.getLibraryIdent().contains("vaesf"))
//            {
//                in = new byte[513];
//            }
//            else if (nativeServices.getLibraryIdent().contains("vaes"))
//            {
//                in = new byte[129];
//            }
//            else
//            {
//                in = new byte[65];
//            }
//
//            nativeCCM.processBytes(in, 0, in.length, new byte[0], 20);
//            fail("zero len but output");
//        }
//        catch (Exception ex)
//        {
//            assertTrue(ex.getMessage().contains("offset past end of array"));
//        }


//        try
//        { // null output array but output generated
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//            byte[] in;
//            if (nativeServices.getLibraryIdent().contains("vaesf"))
//            {
//                in = new byte[513];
//            }
//            else if (nativeServices.getLibraryIdent().contains("vaes"))
//            {
//                in = new byte[129];
//            }
//            else
//            {
//                in = new byte[65];
//            }
//            byte[] out = null;
//
//            // Passes because 32 bytes will not trigger any output.
//            nativeCCM.processBytes(in, 0, in.length, out, 0);
//            fail("null output");
//        }
//        catch (Exception ex)
//        {
//            assertTrue(ex.getMessage().contains("output len too short"));
//        }

//        try
//        { // long enough output array but offset at array.len
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//            byte[] in;
//            if (nativeServices.getLibraryIdent().contains("vaesf"))
//            {
//                in = new byte[513];
//            }
//            else if (nativeServices.getLibraryIdent().contains("vaes"))
//            {
//                in = new byte[129];
//            }
//            else
//            {
//                in = new byte[65];
//            }
//            byte[] out = new byte[65];
//
//            // Passes because 32 bytes will not trigger any output.
//            nativeCCM.processBytes(in, 0, in.length, out, 65);
//            fail("not enough output");
//        }
//        catch (Exception ex)
//        {
//            assertTrue(ex.getMessage().contains("output len too short"));
//        }

//        try
//        { // long enough output array but offset in the middle
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//            byte[] in;
//            if (nativeServices.getLibraryIdent().contains("vaesf"))
//            {
//                in = new byte[513];
//            }
//            else if (nativeServices.getLibraryIdent().contains("vaes"))
//            {
//                in = new byte[129];
//            }
//            else
//            {
//                in = new byte[65];
//            }
//            byte[] out = new byte[65];
//
//            // Passes because 32 bytes will not trigger any output.
//            nativeCCM.processBytes(in, 0, in.length, out, 32);
//            fail("not enough output");
//        }
//        catch (Exception ex)
//        {
//            assertTrue(ex.getMessage().contains("output len too short"));
//        }


//        {
//            // Long enough input to cause loop in native processBytes but output buffer to short after
//            // initial iterations.
//
//            byte[] in = new byte[1024];
//            byte[] out = new byte[1023];
//
//            AESNativeCCM nativeCCM = new AESNativeCCM();
//            nativeCCM.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
//
//            try
//            {
//                nativeCCM.processBytes(in, 0, in.length, out, 0);
//                fail("must through output length exception");
//            }
//            catch (Exception ex)
//            {
//                assertTrue(ex.getMessage().contains("output len too short"));
//            }
//
//        }
//
    }

    @Test
    public void testCCMDoFinal_1()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }


        new AESNativeCCM()
        {
            {
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
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
    public void testCCMDoFinal_2()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
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
    public void testCCMDoFinal_3()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
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
    public void testCCMDoFinal_4()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                {
                    doFinal(new byte[16], 0);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    ex.getMessage().contains("needs to be initialised");
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_5()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
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
    public void testCCMDoFinal_6()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[0];
                    byte[] out = new byte[7];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_7()
        throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[16];
                    byte[] out = new byte[16 + 7];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_8()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[32];
                    byte[] out = new byte[32 + 7];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_9()
        throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[48];
                    byte[] out = new byte[48 + 7];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_10()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[64];
                    byte[] out = new byte[64 + 7];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_12()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[96];
                    byte[] out = new byte[96 + 7];

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_13()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[16 + 16];
                    byte[] out = new byte[15]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_14()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }

        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[33 + 16];
                    byte[] out = new byte[32]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_15()
        throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[49 + 16];
                    byte[] out = new byte[48]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_16()
        throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[65 + 16];
                    byte[] out = new byte[64]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_17()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeCCM()
        {
            {
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[96 + 16];
                    byte[] out = new byte[95]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

    }

    @Test
    public void testCCMDoFinal_18()
        throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }
        new AESNativeCCM()
        {
            { // Verify output length verification failure from native side on encryption.
                try
                { // One byte too short for final with message 128b mac
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] in = new byte[1024 + 15]; // One byte too small to hold tag
                    byte[] out = new byte[1024]; // Too small output by one.

                    int l = processBytes(in, 0, in.length, out, 0);
                    doFinal(out, l);
                    fail("expected too small for encrypt");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };


    }

    @Test
    public void testCCMDoFinal_19()
        throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }
        //
        // Generate a valid cipher text, tag etc.
        //
        AESNativeCCM ccm = new AESNativeCCM();
        ccm.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
        byte[] validResult = new byte[1024 + 16];
        int l = ccm.processBytes(new byte[1024], 0, 1024, validResult, 0);
        ccm.doFinal(validResult, l);
        ccm.reset();

        new AESNativeCCM()
        {
            {
                //
                // Verify invalid cipher text when internal buffer is less than tag len on call to doFinal
                // in decryption.
                //
                try
                { // One byte too short for final with message 128b mac
                    init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                    byte[] out = new byte[1024]; // Too small output by one.
                    int l = processBytes(validResult, 0, 7, out, 0);
                    doFinal(out, l);
                    fail("too short cipher text");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("ciphertext too short"));
                }
            }
        };


        {


            new AESNativeCCM()
            {
                { // Verify there is enough output buffer to hold decryption result on doFinal
                    try
                    { // One byte too short for final with message 128b mac
                        init(false, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[12]));
                        byte[] out = new byte[1024]; // Too small output by one.
                        int l = processBytes(validResult, 0, validResult.length - 1, out, 0);
                        doFinal(new byte[15], 0);
                        fail("too short cipher text");
                    }
                    catch (Exception ex)
                    {
                        assertTrue(ex.getMessage().contains("output buffer too short"));
                    }
                }
            };


        }


    }
}
