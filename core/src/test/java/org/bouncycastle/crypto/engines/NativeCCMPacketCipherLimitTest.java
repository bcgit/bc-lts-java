package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.junit.Test;

/**
 * There are two concurrent implementation of packet cipher
 * This test class exercises exceptions thrown from the JNI layer only
 */
public class NativeCCMPacketCipherLimitTest extends TestCase
{

    @Test
    public void testProcessPacketKeyLen()
    {

        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }


        //
        // Invalid key sizes!
        //
        for (int len : new int[]{15,17, 23,25,31,33}) {
            try
            { // processPacket -- key len too small
                new AESNativeCCMPacketCipher()
                {
                    {
                        processPacket(true, new byte[len], new byte[13], null, 16, new byte[0], 0, 0,
                                new byte[16], 0, 16);
                        fail("keylen invalid");
                    }
                };
            }
            catch (Exception ex)
            {
                TestCase.assertEquals("key must be only 16, 24 or 32 bytes long", ex.getMessage());
            }

        }


        try
        { // processPacket -- null key array
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, null, new byte[13], null, 16, new byte[0], 0, 0, new byte[16], 0,
                            16);
                    fail("key array too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key was null", ex.getMessage());
        }




        // Valid cases

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[13], null, 16, new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[24], new byte[13], null, 16, new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[32], new byte[13], null, 16, new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };
    }

    @Test
    public void testProcessPacketIvLen()
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }


        try
        { // processPacket -- nonce null
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], null, null, 16, null, 0, 0, null, 0, 0);
                    fail("nonce is null");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce is null", ex.getMessage());
        }


        try
        { // processPacket -- nonce too small
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[6], null, 16, null, 0, 0, null, 0, 0);
                    fail("nonce is null");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce must have length from 7 to 13 octets", ex.getMessage());
        }

        try
        { // processPacket -- nonce too small
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[14], null, 16, null, 0, 0, null, 0, 0);
                    fail("nonce is null");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce must have length from 7 to 13 octets", ex.getMessage());
        }




        // Valid cases

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0, new byte[16],
                        0, 16);

            }
        };
    }

    //
    @Test
    public void testProcessPacketOutputArray()
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }


        try
        { // processPacket -- output null
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0, null, 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output was null", ex.getMessage());
        }


        try
        { // processPacket -- output offset negative
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0,
                            new byte[0], -1, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output offset is negative", ex.getMessage());
        }

        try
        { // processPacket -- output len negative
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0,
                            new byte[16], 0, -1);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output len is negative", ex.getMessage());
        }


        try
        { // processPacket -- output buffer too short for offset and len
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0,
                            new byte[16], 1, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short for offset + length", ex.getMessage());
        }

        try
        { // processPacket -- output buffer too short for offset and len
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0,
                            new byte[16], 0, 17);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short for offset + length", ex.getMessage());
        }


        try
        { // processPacket -- output less than input len
            new AESNativeCCMPacketCipher()
            {
                {

                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[16], 0, 16,
                            new byte[15], 0, 15);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }


        //   Valid cases

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[13], null, 16, new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[13], null, 16, new byte[15], 15, 0,
                        new byte[17], 1, 16);
            }
        };
    }

    @Test
    public void testOutputTooShortEncryption()
    {

        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }


        try
        { // processPacket -- output array / len too small to hold cipher text and tag
            new AESNativeCCMPacketCipher()
            {
                {

                    processPacket(true, new byte[16],
                            new byte[13],
                            null,
                            16,
                            new byte[16], 0, 16,
                            new byte[32], 0, 31); // one less than data + tag
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }

        try
        { // processPacket -- output array / len too small to hold cipher text and tag
            new AESNativeCCMPacketCipher()
            {
                {

                    processPacket(true, new byte[16],
                            new byte[13],
                            null,
                            16,
                            new byte[16], 0, 16,
                            new byte[48], 16, 31); // one less than data + tag
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }


        try
        { // processPacket -- output array / len too small to hold cipher text and tag
            new AESNativeCCMPacketCipher()
            {
                {

                    processPacket(false, new byte[16],
                            new byte[13],
                            null,
                            16,
                            new byte[15], 0, 15,
                            new byte[32], 0, 15); // one less than data + tag
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input data too short", ex.getMessage());
        }


    }


    @Test
    public void testProcessPacketInputArray()
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }


        try
        { // processPacket -- input null
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, null, 0, 0, null, 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input was null", ex.getMessage());
        }


        try
        { // processPacket -- input offset negative
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[16], -1, 0,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input offset is negative", ex.getMessage());
        }

        try
        { // processPacket -- input len negative
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[16], 0, -1,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input len is negative", ex.getMessage());
        }


        try
        { // processPacket -- input buffer too short for offset and len
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[16], 1, 16,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input buffer too short for offset + length", ex.getMessage());
        }

        try
        { // processPacket -- input buffer too short for offset and len
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[13], null, 16, new byte[16], 0, 17,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input buffer too short for offset + length", ex.getMessage());
        }

        // Valid cases

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[13],
                        null,
                        16,
                        new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeCCMPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[13], null, 16, new byte[15], 15, 0,
                        new byte[16], 0, 16);
            }
        };
    }


    @Test
    public void testMacLen()
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }

        try
        { //
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true,
                            new byte[16],
                            new byte[13],
                            null,
                            -1,
                            new byte[15], 15, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }


        try
        { //
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true,
                            new byte[16],
                            new byte[13],
                            null,
                            3,
                            new byte[15], 15, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }


        try
        { //
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(true,
                            new byte[16],
                            new byte[13],
                            null,
                            17,
                            new byte[15], 15, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }


        try
        { //
            new AESNativeCCMPacketCipher()
            {
                {
                    getOutputSize(true, 10, -1);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }

        try
        { //
            new AESNativeCCMPacketCipher()
            {
                {
                    getOutputSize(true, 10, 17);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }

        try
        { //
            new AESNativeCCMPacketCipher()
            {
                {
                    getOutputSize(true, 10, 3);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }

        new AESNativeCCMPacketCipher()
        {
            {
                for (int t = 4; t <= 16; t++)
                {
                    getOutputSize(true, 10, t);

                    processPacket(true,
                            new byte[16],
                            new byte[13],
                            null,
                            t,
                            new byte[15], 15, 0,
                            new byte[16], 0, 16);


                }
            }
        };


    }

    @Test
    public void testInputTooShortDecryption()
    {

        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }

        try
        { // processPacket -- input too short for decryption
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(false, new byte[16], new byte[13], null, 16, new byte[16], 1, 15,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input data too short", ex.getMessage());
        }


        try
        { // processPacket -- input too short for decryption
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(false, new byte[16], new byte[13], null, 16, new byte[15], 0, 15,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input data too short", ex.getMessage());
        }


        try
        { // processPacket -- input too short for decryption
            new AESNativeCCMPacketCipher()
            {
                {
                    processPacket(false, new byte[16], new byte[13], null, 5, new byte[15], 0, 4,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input data too short", ex.getMessage());
        }


    }

    @Test
    public void testGetOutputSize()
    {
        if (TestUtil.skipPS())
        {
            System.out.println("Skipping packet cipher test.");
            return;
        }

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }

        try
        { // get output size
            new AESNativeCCMPacketCipher()
            {
                {
                    getOutputSize(true, -1, 13);
                    fail("len negative");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input len is negative", ex.getMessage());
        }


        try
        { // get output size
            new AESNativeCCMPacketCipher()
            {
                {
                    getOutputSize(false, 5, 13);
                    fail("len too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("len parameter invalid", ex.getMessage());
        }

        try
        { // get output size
            new AESNativeCCMPacketCipher()
            {
                {
                    getOutputSize(false, 5, -1);
                    fail("mac size negative");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }


        try
        { // get output size
            new AESNativeCCMPacketCipher()
            {
                {
                    getOutputSize(false, 5, 17);
                    fail("mac size negative");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid mac size", ex.getMessage());
        }


        new AESNativeCCMPacketCipher()
        {
            {
                getOutputSize(false, 13, 13);
            }
        };

        new AESNativeCCMPacketCipher()
        {
            {
                getOutputSize(false, 32, 16);
            }
        };
    }


    public boolean isNativeVariant()
    {
        String variant = CryptoServicesRegistrar.getNativeServices().getVariant();
        if (variant == null || "java".equals(variant))
        {
            return false;
        }

        // May not be ported to native platform, so exercise java version only.
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CCM_PC);
    }

}
