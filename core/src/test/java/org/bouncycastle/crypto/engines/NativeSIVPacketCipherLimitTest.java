package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.junit.Test;

public class NativeSIVPacketCipherLimitTest extends TestCase
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
        for (int len : new int[]{15,17, 24,31,33}) {
            try
            { // processPacket -- key len too small
                new AESNativeGCMSIVPacketCipher()
                {
                    {
                        processPacket(true, new byte[len], new byte[12], null, new byte[0], 0, 0,
                                new byte[16], 0, 16);
                        fail();
                    }
                };
            }
            catch (Exception ex)
            {
                TestCase.assertEquals("key must be only 16, or 32 bytes long", ex.getMessage());
            }

        }








        try
        { // processPacket -- null key array
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, null, new byte[13], null, new byte[0], 0, 0, new byte[16], 0,
                            16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key was null", ex.getMessage());
        }

        // Valid cases

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], null, new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };


        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[32], new byte[12], null, new byte[16], 0, 0,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], null, null, null, 0, 0, null, 0, 0);
                    fail("nonce is null");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce is null", ex.getMessage());
        }

        // Nonce can only be 12 bytes
        // Valid cases

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

    }

    @Test
    public void testProcessPacketAADLen()
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


        // null aad is valid
        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        // ad array zero and len zero
        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], new byte[0], new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        // od ok
        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], new byte[10], new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, null, 0, 0, null, 0, 0);
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[16], -1, 0,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[16], 0, -1,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[16], 1, 16,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[16], 0, 17,
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

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[12],
                        null,

                        new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], null, new byte[15], 15, 0,
                        new byte[16], 0, 16);
            }
        };
    }

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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0, null, 0, 0);
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {

                    processPacket(true, new byte[16], new byte[12], null, new byte[16], 0, 16,
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

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], null, new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[12], null, new byte[15], 15, 0,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {

                    processPacket(true, new byte[16],
                            new byte[12],
                            null,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {

                    processPacket(true, new byte[16],
                            new byte[12],
                            null,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {

                    processPacket(false, new byte[16],
                            new byte[12],
                            null,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(false, new byte[16], new byte[12], null, new byte[16], 1, 15,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(false, new byte[16], new byte[12], null, new byte[15], 0, 15,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(false, new byte[16], new byte[12], null, new byte[15], 0, 4,
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    getOutputSize(true, -1);
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
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    getOutputSize(false, 15);
                    fail("len too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("len parameter invalid", ex.getMessage());
        }


        new AESNativeGCMSIVPacketCipher()
        {
            {
                getOutputSize(false, 16);
            }
        };

        new AESNativeGCMSIVPacketCipher()
        {
            {
                getOutputSize(true, 0);
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

        // May not be ported to native platform.
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCMSIV_PC);
    }
}
