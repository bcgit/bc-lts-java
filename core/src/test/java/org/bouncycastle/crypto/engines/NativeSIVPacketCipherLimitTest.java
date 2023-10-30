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


        try
        { // processPacket -- keylen negative
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], -1, new byte[13], 13, null, 0,  new byte[0], 0, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key must be only 16, or 32 bytes long", ex.getMessage());
        }


        try
        { // processPacket -- keylen
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 15, new byte[13], 13,  null, 0, new byte[0], 0, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key must be only 16, or 32 bytes long", ex.getMessage());
        }


        try
        { // processPacket -- keylen ok but array len too small
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[15], 16, new byte[13], 13,  null, 0, new byte[0], 0, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key array is less than keyLen", ex.getMessage());
        }

        try
        { // processPacket -- null key array
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, null, 16, new byte[13], 13, null, 0, new byte[0], 0, 0, new byte[16], 0,
                            16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key was null", ex.getMessage());
        }


        try
        { // processPacket -- invalid key size
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[32], 17, new byte[13], 13,  null, 16, new byte[0], 0, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key must be only 16, or 32 bytes long", ex.getMessage());
        }


        try
        { // processPacket -- invalid key size
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[36], 24, new byte[13], 13, null, 16, new byte[0], 0, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key must be only 16, or 32 bytes long", ex.getMessage());
        }

        try
        { // processPacket -- invalid key size
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[36], 33, new byte[13], 13, null, 16, new byte[0], 0, 0,
                            new byte[16], 0, 16);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key must be only 16, or 32 bytes long", ex.getMessage());
        }


        // Valid cases

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[16], 12, null, 0, new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };


        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[32], 32, new byte[17], 12, null, 0,  new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };


        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[33], 16, new byte[17], 12, null, 0,  new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };


        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[33], 32, new byte[17], 12, null, 0, new byte[16], 0, 0,
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
                    processPacket(true, new byte[16], 16, null, -1, null, 0,  null, 0, 0, null, 0, 0);
                    fail("nonce is null");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce is null", ex.getMessage());
        }


        try
        { // processPacket -- nonce len negative
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], -1, null, 0,  null, 0, 0, null, 0, 0);
                    fail("len is negative");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce len is negative", ex.getMessage());
        }


        try
        { // processPacket -- array less than len
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[0], 1, null, 0,  null, 0, 0, null, 0, 0);
                    fail("array less then len");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce len past end of nonce array", ex.getMessage());
        }


        try
        { // processPacket -- nonce len out of range
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[14], 6, null, 0,  null, 0, 0, null, 0, 0);
                    fail("len out of range");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("invalid nonce", ex.getMessage());
        }

        // Nonce can only be 12 bytes


        // Valid cases

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[14], 12, null, 0,  new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[12], 12, null, 0,  new byte[0], 0, 0, new byte[16],
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
                processPacket(true, new byte[16], 16, new byte[14], 12, null, 0,  new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };


        try
        { // ad null but length non zero
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 1,  null, 0, 0, null, 0, 0);
                    fail("null ad array with non zero length");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("ad len non zero but ad array is null", ex.getMessage());
        }


        try
        { // ad len is negative
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[13], 12, new byte[0], -1,  null, 0, 0, null, 0,
                            0);
                    fail("ad len negative");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("ad len is negative", ex.getMessage());
        }

        try
        { // ad len past end of ad array
            new AESNativeGCMSIVPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[13], 12, new byte[0], 1, null, 0, 0, null, 0, 0);
                    fail("ad len past end of ad array");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("ad len past end of ad array", ex.getMessage());
        }


        // ad array zero and len zero
        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[14], 12, new byte[0], 0,  new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        // ad partial array
        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[14], 12, new byte[10], 5, new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        // ad all of array
        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[14], 12, new byte[10], 10,  new byte[0], 0, 0,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  null, 0, 0, null, 0, 0);
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  new byte[16], -1, 0,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  new byte[16], 0, -1,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0, new byte[16], 1, 16,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0, new byte[16], 0, 17,
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
                        new byte[16], 16,
                        new byte[13], 12,
                        null, 0,

                        new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[13], 12, null, 0, new byte[15], 15, 0,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  new byte[0], 0, 0, null, 0, 0);
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  new byte[0], 0, 0,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  new byte[0], 0, 0,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  new byte[0], 0, 0,
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
                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0, new byte[0], 0, 0,
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

                    processPacket(true, new byte[16], 16, new byte[13], 12, null, 0,  new byte[16], 0, 16,
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
                processPacket(true, new byte[16], 16, new byte[13], 12, null, 0, new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        new AESNativeGCMSIVPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[13], 12, null, 0, new byte[15], 15, 0,
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

                    processPacket(true, new byte[16], 16,
                            new byte[13], 12,
                            null, 0,
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

                    processPacket(true, new byte[16], 16,
                            new byte[13], 12,
                            null, 0,
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

                    processPacket(false, new byte[16], 16,
                            new byte[13], 12,
                            null, 0,
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
                    processPacket(false, new byte[16], 16, new byte[13], 12, null, 0,  new byte[16], 1, 15,
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
                    processPacket(false, new byte[16], 16, new byte[13], 12, null, 0,  new byte[15], 0, 15,
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
                    processPacket(false, new byte[16], 16, new byte[13], 12, null, 0,  new byte[15], 0, 4,
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
                    getOutputSize(true,  -1);
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
                    getOutputSize(false,  15);
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
                getOutputSize(false,  16);
            }
        };

        new AESNativeGCMSIVPacketCipher()
        {
            {
                getOutputSize(true,  0);
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
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCMSIV_PC);
    }
}
