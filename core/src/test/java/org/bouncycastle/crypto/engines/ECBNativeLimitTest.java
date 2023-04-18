package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Before;
import org.junit.Test;

public class ECBNativeLimitTest extends TestCase
{
    @Before
    public void setUp()
    {

    }

    @Test
    public void testECBInit()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native ecb and no skip set for it");
                return;
            }
            System.out.println("Skipping ECB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }


        //
        // Calling native methods directly.
        //

        new AESNativeEngine()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    init(ref, null);
                    dispose(ref);
                    fail("accepted null key");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof NullPointerException);
                    TestCase.assertTrue(ex.getMessage().contains("key was null"));
                }
                dispose(ref);
            }
        };


        new AESNativeEngine()
        {
            {
                long ref = makeInstance(16, true);
                try
                {
                    init(ref, new byte[15]);
                    dispose(ref);
                    fail("invalid key size");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof IllegalArgumentException);
                    TestCase.assertTrue(ex.getMessage().contains("key must be only 16,24 or 32 bytes long"));

                }
                dispose(ref);
            }
        };

        new AESNativeEngine()
        {
            {
                long ref = 0;
                try
                {
                    ref = makeInstance(15, true);
                    dispose(ref);
                    fail("invalid key size for make instance");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof IllegalArgumentException);
                    TestCase.assertTrue(ex.getMessage().contains("key must be only 16,24 or 32 bytes long"));

                }
                dispose(ref);
            }
        };


        //---


        new AESNativeEngine()
        {
            {
                //
                // Passing null key causes some failure.
                //
                try
                {
                    KeyParameter piv = new KeyParameter(new byte[0])
                    {
                        @Override
                        public byte[] getKey()
                        {
                            return null;
                        }
                    };
                    init(true, piv);
                    fail("accepted null key");
                }
                catch (Exception ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }
            }
        };

        new AESNativeEngine()
        {
            {
                //
                // Pass invalid key size
                //
                try
                {
                    KeyParameter piv = new KeyParameter(new byte[15]);
                    init(true, piv);
                    fail("accepted invalid key size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("key must be"));
                }
            }

        };

        new AESNativeEngine()
        {
            {
                //
                // Pass invalid key size
                //
                try
                {
                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[15]), new byte[0]);
                    init(true, piv);
                    fail("unknown param object");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("invalid parameter passed to AES"));
                }
            }

        };

    }


    public void testECBProcessBlock()
            throws Exception
    {

        if (!TestUtil.hasNativeService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native", "").contains("ecb"))
            {
                fail("Skipping Limit Test: " + TestUtil.errorMsg());
            }
            else
            {
                assertTrue("Skipped via property test.bcfips.ignore.native", true);
            }
            return;
        }

        new AESNativeEngine()
        {
            {

                //
                // null input array
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(null, 0, new byte[16], 0);
                    fail("accepted null input array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }

            }
        };
        new AESNativeEngine()
        {
            {
                //
                // null output array
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(new byte[16], 0, null, 0);
                    fail("accepted null output array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // negative input offset
                //

                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(new byte[0], -1, new byte[0], 0);
                    fail("accepted negative in offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input offset is negative"));
                }

            }
        };
        new AESNativeEngine()
        {
            {
                //
                // Negative output offset
                //

                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(new byte[0], 0, new byte[0], -1);
                    fail("accepted negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output offset is negative"));
                }

            }
        };
        new AESNativeEngine()
        {
            {

                //
                // input buffer too short
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(new byte[15], 0, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {

                //
                // input buffer too short for offset
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(new byte[16], 1, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {

                //
                // Output buffer to short
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(new byte[16], 0, new byte[15], 0);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {

                //
                // Output buffer too short for offset
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlock(new byte[16], 0, new byte[16], 1);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }

            }
        };
        new AESNativeEngine()
        {
            {

                //
                // Not initialized
                //
                try
                {
                    processBlock(new byte[16], 0, new byte[16], 0);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("not initialized"));
                }
            }
        };

    }


    @Test
    public void testECBProcessBlocks()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/ECB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("ecb"))
            {
                fail("no native ecb and no skip set for it");
                return;
            }
            System.out.println("Skipping ECB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }

        new AESNativeEngine()
        {
            {

                //
                // Null input array
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(null, 0, 1, new byte[16], 0);
                    fail("accepted null input array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }
            }
        };

        new AESNativeEngine()
        {
            {
                //
                // Null output array
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[16], 0, 1, null, 0);
                    fail("accepted null output array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // Negative input offset.
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[0], -1, 1, new byte[0], 0);
                    fail("accepted negative in offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input offset is negative"));
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // Negative block count.
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[0], 0, -1, new byte[0], 0);
                    fail("accepted negative block count ");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("blockCount is negative"));
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // Negative output offset
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[0], 0, 1, new byte[0], -1);
                    fail("accepted negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output offset is negative"));
                }
            }
        };
        new AESNativeEngine()
        {
            {

                //
                // Two short input buffer for block, offset 0
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[15], 0, 1, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {

                //
                // Too short input buffer with offset of one, last byte read would be outside
                // of byte array.
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[16], 1, 1, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                //Multiblock, too short input array offset 0
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[31], 0, 2, new byte[32], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // Multiblock, too short input array, last byte read would be outside of input array
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[32], 1, 2, new byte[32], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {

                //
                // Too short output buffer.
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[16], 0, 1, new byte[15], 0);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // Too short output buffer for output offset, last byte written would be outside of
                // array.
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[16], 0, 1, new byte[16], 1);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // multiblock too short output buffer, last byte written would outside of array
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[32], 0, 2, new byte[31], 0);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };
        new AESNativeEngine()
        {
            {
                //
                // multiblock, too short output buffer for output offset, last byte written would
                // be outside of output buffer.
                //
                try
                {
                    init(true, new KeyParameter(new byte[16]));
                    processBlocks(new byte[32], 0, 2, new byte[32], 1);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

        new AESNativeEngine()
        {
            {

                //
                // Valid inputs but not initialised.
                //
                try
                {
                    processBlocks(new byte[16], 0, 1, new byte[16], 0);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("not initialized"));
                }
            }
        };

    }
}
