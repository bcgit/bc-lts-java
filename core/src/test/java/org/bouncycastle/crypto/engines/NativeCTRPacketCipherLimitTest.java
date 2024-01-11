package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.junit.Test;

public class NativeCTRPacketCipherLimitTest extends TestCase
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
                new AESNativeCTRPacketCipher()
                {
                    {
                        processPacket(true, new byte[len], new byte[13],  new byte[0], 0, 0,
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




        // Valid cases

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[16],  new byte[16],  new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[24],  new byte[16],  new byte[16], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[32],  new byte[16],  new byte[16], 0, 0,
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  null,  null, 0, 0, null, 0, 0);
                    fail("nonce is null");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce is null", ex.getMessage());
        }

        try
        { // processPacket -- nonce len out of range
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[17],  null, 0, 0, null, 0, 0);
                    fail("len out of range");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce len must be from 8 to 16 bytes", ex.getMessage());
        }

        try
        { // processPacket -- nonce len out of range
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[7],  null, 0, 0, null, 0, 0);
                    fail("len out of range");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("nonce len must be from 8 to 16 bytes", ex.getMessage());
        }


        // Valid cases

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[16],  new byte[8],  new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[16],  new byte[16],  new byte[0], 0, 0, new byte[16],
                        0, 16);

            }
        };
    }


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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  null, 0, 0, null, 0, 0);
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[16], -1, 0,
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[16], 0, -1,
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],
                             new byte[16], 1, 16,
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[16], 0, 17,
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

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[16],
                        new byte[0], 0, 0,
                        new byte[16], 0, 16);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[16],  new byte[16],  new byte[15], 15, 0,
                        new byte[16], 0, 16);
            }
        };
    }


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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[0], 0, 0, null, 0, 0);
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[0], 0, 0,
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[0], 0, 0,
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[0], 0, 0,
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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true, new byte[16],  new byte[16],  new byte[0], 0, 0,
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
            new AESNativeCTRPacketCipher()
            {
                {

                    processPacket(true, new byte[16],  new byte[16],  new byte[16], 0, 16,
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

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[16], new byte[16],  new byte[0], 0, 0, new byte[16],
                        0, 16);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true, new byte[16],  new byte[16],  new byte[15], 15, 0,
                        new byte[17], 1, 16);
            }
        };
    }


    @Test
    public void testOutputLength() {

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
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true,
                            new byte[16],
                            new byte[16],
                            new byte[1], 0, 1,
                            new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }


        try
        { // processPacket -- output null
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true,
                            new byte[16],
                            new byte[16],
                            new byte[2], 1, 1,
                            new byte[1], 1, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }


        try
        { // processPacket -- output null
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true,
                            new byte[16],
                            new byte[16],
                            new byte[2], 1, 1,
                            new byte[2], 2, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }


        try
        { // processPacket -- output null
            new AESNativeCTRPacketCipher()
            {
                {
                    processPacket(true,
                            new byte[16],
                            new byte[16],
                            new byte[4], 0, 4,
                            new byte[4], 1, 3);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }


        // valid cases

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[16],
                        new byte[4], 0, 4,
                        new byte[5], 1, 4);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[16],
                        new byte[0], 0, 0,
                        new byte[0], 0, 0);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[16],
                        new byte[0], 0, 0,
                        new byte[1], 1, 0);
            }
        };


        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[16],
                        new byte[0], 0, 0,
                        new byte[8], 0, 8);
            }
        };

        new AESNativeCTRPacketCipher()
        {
            {
                processPacket(true,
                        new byte[16],
                        new byte[16],
                        new byte[2], 1, 1,
                        new byte[8], 0, 8);
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
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CTR_PC);
    }
}
