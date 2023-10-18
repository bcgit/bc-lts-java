package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.ExceptionMessages;
import org.bouncycastle.crypto.NativeServices;
import org.junit.Test;

/**
 * There are two concurrent implementation of packet cipher
 * This test class exercises exceptions thrown from the JNI layer only
 */
public class NativeCBCPacketCipherLimitTest extends TestCase
{

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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[0], 0, 0, null, 0, 0);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 16, new byte[0], -1, 0);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 16, new byte[16], 0, -1);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 16, new byte[16], 1, 16);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 16, new byte[16], 0, 17);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 16, new byte[15], 0, 15);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("output buffer too short", ex.getMessage());
        }


        // Valid cases

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[16], 16, new byte[0], 0, 0, new byte[0], 0, 0);
            }
        };

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[16], 16, new byte[15], 15, 0, new byte[15], 15, 0);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, null, 0, 0, null, 0, 0);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], -1, 0, new byte[0], 0, 0);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, -1, new byte[0], 0, 0);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 1, 16, new byte[0], 0, 0);
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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 17, new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input buffer too short for offset + length", ex.getMessage());
        }



        try
        { // processPacket -- input not mod 16
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 16, new byte[15], 0, 15, new byte[0], 0, 0);
                    fail();
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input len not multiple of block size", ex.getMessage());
        }


        // Valid cases

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[16], 16, new byte[0], 0, 0, new byte[0], 0, 0);
            }
        };

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[16], 16, new byte[15], 15, 0, new byte[0], 0, 0);
            }
        };
    }

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
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], -1, new byte[16], 16, null, 0, 0, null, 0, 0);
                    fail("keylen too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key must be only 16, 24 or 32 bytes long", ex.getMessage());
        }


        try
        { // processPacket -- keylen
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 15, new byte[16], 16, null, 0, 0, null, 0, 0);
                    fail("keylen too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key must be only 16, 24 or 32 bytes long", ex.getMessage());
        }


        try
        { // processPacket -- keylen ok but array len too small
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[15], 16, new byte[16], 16, null, 0, 0, null, 0, 0);
                    fail("key array too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key array is less than keyLen", ex.getMessage());
        }

        try
        { // processPacket -- null key array
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, null, 16, new byte[16], 16, null, 0, 0, null, 0, 0);
                    fail("key array too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("key was null", ex.getMessage());
        }

        // Valid cases

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 16, new byte[16], 0, 16);
            }
        };

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[24], 24, new byte[17], 16, new byte[16], 0, 16, new byte[16], 0, 16);
            }
        };

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[32], 32, new byte[17], 16, new byte[16], 0, 16, new byte[16], 0, 16);
            }
        };


        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[33], 16, new byte[17], 16, new byte[16], 0, 16, new byte[16], 0, 16);
            }
        };

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[33], 24, new byte[17], 16, new byte[16], 0, 16, new byte[16], 0, 16);
            }
        };

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[33], 32, new byte[17], 16, new byte[16], 0, 16, new byte[16], 0, 16);
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
        { // processPacket -- keylen negative
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], -1, null, 0, 0, null, 0, 0);
                    fail("nonce too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("iv must be only 16 bytes", ex.getMessage());
        }

        try
        { // processPacket -- keylen negative
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[16], 15, null, 0, 0, null, 0, 0);
                    fail("nonce too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("iv must be only 16 bytes", ex.getMessage());
        }


        try
        { // processPacket -- keylen negative
            new AESNativeCBCPacketCipher()
            {
                {
                    processPacket(true, new byte[16], 16, new byte[15], 16, null, 0, 0, null, 0, 0);
                    fail("nonce array too small");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("iv array length is less than ivLen", ex.getMessage());
        }


        // Valid cases

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[16], 16, new byte[16], 0, 16, new byte[16], 0, 16);
            }
        };

        new AESNativeCBCPacketCipher()
        {
            {
                processPacket(true, new byte[16], 16, new byte[17], 16, new byte[16], 0, 16, new byte[16], 0, 16);
            }
        };

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
            new AESNativeCBCPacketCipher()
            {
                {
                    getOutputSize(-1);
                    fail("negaive");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input len is negative", ex.getMessage());
        }


        try
        { // get output size
            new AESNativeCBCPacketCipher()
            {
                {
                    getOutputSize(15);
                    fail("not mod 16");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input len not multiple of block size", ex.getMessage());
        }

        try
        { // get output size
            new AESNativeCBCPacketCipher()
            {
                {
                    getOutputSize(33);
                    fail("not mod 16");
                }
            };
        }
        catch (Exception ex)
        {
            TestCase.assertEquals("input len not multiple of block size", ex.getMessage());
        }

    }


    public boolean isNativeVariant()
    {
        String variant = CryptoServicesRegistrar.getNativeServices().getVariant();
        if (variant == null || "java".equals(variant))
        {
            return false;
        }

        // May not be ported to native platform, so exercise java version only.
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_CBC_PC);
    }

}
