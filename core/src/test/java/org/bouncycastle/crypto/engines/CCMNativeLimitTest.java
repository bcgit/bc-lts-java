package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Before;
import org.junit.Test;

public class CCMNativeLimitTest
        extends TestCase
{

    public CCMNativeLimitTest()
    {
        super();
    }

    @Before
    public void setUp()
    {

    }

    static boolean skipIfNotSupported()
    {
        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CCM"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("ccm"))
            {
                fail("no native ccm and no skip set for it");
                return false;
            }
            System.out.println("Skipping CCM native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return true;
        }
        return false;
    }


    /**
     * Test the jni layer throws exceptions as required for broken input.
     * This tests the common input validation issues by bypassing the java layer and going to the
     * jni layer directly and passing parameters to that.
     *
     * @throws Exception
     */
    @Test
    public void testCCMProcessPacket_1() throws Exception
    {
        if (skipIfNotSupported())
        {
            return;
        }


        // Null Input array
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, null, 0, 0, null, 0, new byte[16], 0);
                    dispose(ref);
                    fail("null input array");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input was null"));
                }
                dispose(ref);
            }

        };

        // Negative input offset
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], -1, 0, null, 0, new byte[16], 0);
                    dispose(ref);
                    fail("negative input offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input offset was negative"));
                }
                dispose(ref);
            }

        };

        // Input too short but zero length
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], 17, 0, null, 0, new byte[16], 0);
                    dispose(ref);
                    fail("input buffer too short 1");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
                dispose(ref);
            }
        };


        // Input too short, with length and zero offset
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[0], 0, 1, null, 0, new byte[16], 0);
                    dispose(ref);
                    fail("input buffer too short with len and zero offset on zero len array");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
                dispose(ref);
            }
        };


        // Output is null
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], 0, 16, null, 0, null, 0);
                    dispose(ref);
                    fail("output buffer is null");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output was null"));
                }
                dispose(ref);
            }
        };

        // Output offset is negative
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], 0, 16, null, 0, new byte[0], -1);
                    dispose(ref);
                    fail("output offset is negative");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output offset was negative"));
                }
                dispose(ref);
            }
        };


        // Output offset is too short
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], 0, 16, null, 0, new byte[0], 1);
                    dispose(ref);
                    fail("output buffer too short");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
                dispose(ref);
            }
        };


        // AAD can be null, so we will not test that, but we can test offsets
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], 0, 16, new byte[0], -1, new byte[16], 0);
                    dispose(ref);
                    fail("aad len is negative");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("aad length was negative"));
                }
                dispose(ref);
            }
        };


        // AAD len past end of aad array
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], 0, 16, new byte[0], 1, new byte[16], 0);
                    dispose(ref);
                    fail("aad len past end of aad array");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("aad length past end of array"));
                }
                dispose(ref);
            }
        };

        // AAD array null but length defined
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);
                    processPacket(ref, new byte[16], 0, 16, null, 1, new byte[16], 0);
                    dispose(ref);
                    fail("aad null but length defined");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("aad null but length not zero"));
                }
                dispose(ref);
            }
        };

    }


    /**
     * Test the jni layer throws exceptions as required if the input is superficially
     * valid but an error would occur while processing is underway.
     *
     * @throws Exception
     */
    public void testCCMProcessPacket_2() throws Exception
    {

        if (skipIfNotSupported())
        {
            return;
        }


        // Test where output array is less than required.
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    byte[] message = new byte[32];
                    Arrays.fill(message, (byte) 1);

                    initNative(ref, true, new byte[16], new byte[12], null, 0, 32);

                    int rLen = getOutputSize(ref, message.length);
                    byte[] resp = new byte[rLen - 1];
                    processPacket(ref, message, 0, message.length, null, 0, resp, 0);
                    dispose(ref);
                    fail("invalid output len -- encryption");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
                dispose(ref);
            }

        };


        String ct = "6fc65eb3e3b586471fdccab9961093bb32ca67934a977dd8949e79220d21b2434684d186";

        // Test in decryption where the output is too short for the plain text.
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    byte[] message = Hex.decode(ct);

                    initNative(ref, false, new byte[16], new byte[12], null, 0, 32);

                    int rLen = getOutputSize(ref, message.length);
                    byte[] resp = new byte[rLen - 1];
                    processPacket(ref, message, 0, message.length, null, 0, resp, 0);
                    dispose(ref);
                    fail("invalid output len -- decryption");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
                dispose(ref);
            }

        };


        // Test in decryption where input is less than mac len
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    byte[] message = Hex.decode(ct);

                    initNative(ref, false, new byte[16], new byte[12], null, 0, 32);

                    int rLen = getOutputSize(ref, message.length);
                    byte[] resp = new byte[rLen - 1];
                    processPacket(ref, message, 0, 3, null, 0, resp, 0);
                    dispose(ref);
                    fail("invalid output len -- decryption");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("ciphertext too short"));
                }
                dispose(ref);
            }
        };


        // Successful decryption just for sanity checking in this context
        new AESNativeCCM()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    byte[] message = Hex.decode(ct);
                    initNative(ref, false, new byte[16], new byte[12], null, 0, 32);
                    int rLen = getOutputSize(ref, message.length);
                    byte[] resp = new byte[rLen];
                    processPacket(ref, message, 0, message.length, null, 0, resp, 0);

                    byte[] expected = new byte[32];
                    Arrays.fill(expected, (byte) 1);
                    TestCase.assertTrue(Arrays.areEqual(expected, resp));

                }
                finally
                {
                    dispose(ref);
                }
            }
        };


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
                    initNative(ref, true, new byte[16], new byte[12], null, 0, 31);
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
                    initNative(ref, true, new byte[16], new byte[14], null, 0, 32);
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
                    initNative(ref, true, new byte[15], new byte[10], null, 0, 128);
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
                    initNative(ref, true, new byte[16], null, null, 0, 128);
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


    }

    @Test
    public void testCCMProcessByte6() throws Exception
    {


        if (skipIfNotSupported())
        {
            return;
        }


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
