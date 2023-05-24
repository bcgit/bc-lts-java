package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.junit.Assert.*;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;


public class CBCNativeLimitTest extends TestCase
{
    @Before
    public void setUp()
    {
//        FipsStatus.isReady();
//        NativeLoader.setNativeEnabled(true);
    }

    @Test
    public void testCBCInit()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CBC"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
               fail("no native cbc and no skip set for it");
                return;
            }
            System.out.println("Skipping CBC native concordance test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }


        new AESNativeCBC()
        {
            {
                long ref = makeNative(16, true);
                try
                {
                    init(ref, null, new byte[16]);
                    dispose(ref);
                    TestCase.fail("accepted null key");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof NullPointerException);
                    TestCase.assertTrue(ex.getMessage().contains("key was null"));
                }
                dispose(ref);
            }
        };

        new AESNativeCBC()
        {
            {
                long ref = makeNative(16, true);
                try
                {
                    init(ref, new byte[16], null);
                    dispose(ref);
                    TestCase.fail("accepted null iv");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof NullPointerException);
                    TestCase.assertTrue(ex.getMessage().contains("iv is null"));
                }
                dispose(ref);
            }
        };


        new AESNativeCBC()
        {
            {
                long ref = makeNative(16, true);
                try
                {
                    init(ref, new byte[15], new byte[16]);
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


        new AESNativeCBC()
        {
            {
                long ref = makeNative(16, true);
                try
                {
                    init(ref, new byte[16], new byte[15]);
                    dispose(ref);
                    fail("invalid iv size");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof IllegalArgumentException);
                    TestCase.assertTrue(ex.getMessage().contains("iv must be only 16 bytes"));
                }
                dispose(ref);
            }
        };


        new AESNativeCBC()
        {
            {
                long ref = 0;
                try
                {
                    ref = makeNative(15, true);
                    dispose(ref);
                    fail("accepted invalid key len in makeNative");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof IllegalArgumentException);
                    TestCase.assertTrue(ex.getMessage().contains("key must be only 16,24,or 32 bytes long"));
                }
                dispose(ref);
            }
        };


        new AESNativeCBC()
        {
            {
                try
                {
                    init(false, new ParametersWithIV(null, new byte[16]));
                    fail("change state to enc with no key");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("not previously initialized with a key"));
                }
            }

        };

        new AESNativeCBC()
        {
            {
                try
                {
                    init(false, null);
                    fail("change state to enc with no key");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("not previously initialized with a key"));
                }
            }

        };


        new AESNativeCBC()
        {
            {
                try
                {
                    init(true, new ParametersWithIV(null, new byte[16]));
                    fail("no initial key but attempt to change iv");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex.getMessage().contains("without providing key"));
                }
            }

        };


        new AESNativeCBC()
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
                    assertTrue(ex instanceof NullPointerException);
                }

                //
                // Passing null key causes some failure
                //
            }
        };

        new AESNativeCBC()
        {
            {
                try
                {
                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[0])
                    {
                        @Override
                        public byte[] getKey()
                        {
                            return null;
                        }
                    }, new byte[16]);
                    init(true, piv);
                    fail("accepted null key");
                }
                catch (Exception ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }

            }
        };

        new AESNativeCBC()
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
                    assertTrue(ex.getMessage().contains("same length as block size"));
                }

            }
        };

        new AESNativeCBC()
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


                //
                // Key changing
                //

                ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]);
                init(true, piv);
                init(true, new KeyParameter(new byte[16]));
                init(true, null);


                piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]);
                init(false, piv);
                init(false, new KeyParameter(new byte[16]));


                try
                {
                    init(true, null);
                    fail("change state without key");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("cannot change encrypting state"));
                }


            }

        };
    }

    @Test
    public void testCBCProcessBlock()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CBC"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native cbc and no skip set for it");
                return;
            }
            System.out.println("Skipping CBC native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }

        new AESNativeCBC()
        {
            {

                //
                // null input array
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(null, 0, new byte[16], 0);
                    fail("accepted null input array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }

            }
        };

        new AESNativeCBC()
        {
            {


                //
                // null output array
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(new byte[16], 0, null, 0);
                    fail("accepted null output array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }
            }
        };

        new AESNativeCBC()
        {
            {

                //
                // negative input offset
                //

                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(new byte[0], -1, new byte[0], 0);
                    fail("accepted negative in offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input offset is negative"));
                }

            }
        };

        new AESNativeCBC()
        {
            {

                //
                // Negative output offset
                //

                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(new byte[0], 0, new byte[0], -1);
                    fail("accepted negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output offset is negative"));
                }

            }
        };

        new AESNativeCBC()
        {
            {

                //
                // input buffer too short
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(new byte[15], 0, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }

            }
        };

        new AESNativeCBC()
        {
            {

                //
                // input buffer too short for offset
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(new byte[16], 1, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };

        new AESNativeCBC()
        {
            {

                //
                // Output buffer to short
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(new byte[16], 0, new byte[15], 0);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }

            }
        };

        new AESNativeCBC()
        {
            {

                //
                // Output buffer too short for offset
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlock(new byte[16], 0, new byte[16], 1);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

        new AESNativeCBC()
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
    public void testCBCProcessBlocks()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CBC"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native cbc and no skip set for it");
                return;
            }
            System.out.println("Skipping CBC native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }

        new AESNativeCBC()
        {
            {
                //
                // Null input array
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(null, 0, 1, new byte[16], 0);
                    fail("accepted null input array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }
            }
        };

        new AESNativeCBC()
        {
            {
                //
                // Null output array
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[16], 0, 1, null, 0);
                    fail("accepted null output array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }
            }
        };
        new AESNativeCBC()
        {
            {
                //
                // Negative input offset.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[0], -1, 1, new byte[0], 0);
                    fail("accepted negative in offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input offset is negative"));
                }
            }
        };

        new AESNativeCBC()
        {
            {
                //
                // Negative block count.
                //

                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[0], 0, -1, new byte[0], 0);
                    fail("accepted negative block count ");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("blockCount is negative"));
                }
            }
        };
        new AESNativeCBC()
        {
            {
                //
                // Negative output offset
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[0], 0, 1, new byte[0], -1);
                    fail("accepted negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output offset is negative"));
                }
            }
        };

        new AESNativeCBC()
        {
            {
                //
                // Two short input buffer for block, offset 0
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[15], 0, 1, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }

            }
        };
        new AESNativeCBC()
        {
            {
                //
                // Too short input buffer with offset of one, last byte read would be outside
                // of byte array.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[16], 1, 1, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }

            }
        };

        new AESNativeCBC()
        {
            {
                //
                //Multiblock, too short input array offset 0
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[31], 0, 2, new byte[32], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };

        new AESNativeCBC()
        {
            {
                //
                // Multiblock, too short input array, last byte read would be outside of input array
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[32], 1, 2, new byte[32], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };

        new AESNativeCBC()
        {
            {

                //
                // Too short output buffer.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[16], 0, 1, new byte[15], 0);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };
        new AESNativeCBC()
        {
            {
                //
                // Too short output buffer for output offset, last byte written would be outside of
                // array.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[16], 0, 1, new byte[16], 1);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

        new AESNativeCBC()
        {
            {
                //
                // multiblock too short output buffer, last byte written would outside of array
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[32], 0, 2, new byte[31], 0);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

        new AESNativeCBC()
        {
            {
                //
                // multiblock, too short output buffer for output offset, last byte written would
                // be outside of output buffer.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBlocks(new byte[32], 0, 2, new byte[32], 1);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };
        new AESNativeCBC()
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
