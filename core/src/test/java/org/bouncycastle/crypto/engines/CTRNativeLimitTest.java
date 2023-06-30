package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CTRNativeLimitTest extends TestCase
{
    @Before
    public void setUp()
    {
//        FipsStatus.isReady();
//        NativeLoader.setNativeEnabled(true);
    }


    static boolean skipIt() {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CTR"))
        {
            if (!System.getProperty("test.bclts.ignore.native","").contains("cbc"))
            {
                fail("no native cfb and no skip set for it");
                return false;
            }
            System.out.println("Skipping CFB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return true;
        }
        return false;
        
    }


    // ctr


    @Test
    public void testCTRInit2()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        //--- calls to native methods

        new AESNativeCTR()
        {
            {
                long ref = makeCTRInstance();
                try
                {
                    init(ref, null, new byte[16]);
                    dispose(ref);
                    fail("accepted null key");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof IllegalArgumentException);
                    TestCase.assertTrue(ex.getMessage().contains("cannot replace iv unless key was previously supplied"));
                }
                dispose(ref);
            }
        };

    }

    @Test
    public void testCTRInit3()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
        {
            {
                long ref = makeCTRInstance();
                try
                {
                    init(ref, new byte[16], null);
                    dispose(ref);
                    fail("accepted null iv");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof NullPointerException);
                    TestCase.assertTrue(ex.getMessage().contains("iv was null"));
                }
                dispose(ref);
            }
        };




    }

    @Test
    public void testCTRInit4()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
        {
            {
                long ref = makeCTRInstance();
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





    }

    @Test
    public void testCTRInit5()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
        {
            {
                long ref = makeCTRInstance();
                try
                {
                    init(ref, new byte[16], new byte[7]);
                    dispose(ref);
                    fail("invalid iv size");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof IllegalArgumentException);
                    TestCase.assertTrue(ex.getMessage().contains("iv len must be from 8 to 16 bytes"));
                }
                dispose(ref);
            }
        };

    }


    @Test
    public void testCTRInit6()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        // ---

        new AESNativeCTR()
        {
            {

                //
                // invalid length iv
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[7]));
                    fail("invalid iv accepted");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex.getMessage().contains("at least: 8 bytes"));
                }
            }

        };

    }

    @Test
    public void testCTRInit7()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
        {
            {

                //
                // no key set
                //
                try
                {
                    init(true, new ParametersWithIV(null, new byte[8]));
                    fail("invalid iv accepted");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex.getMessage().contains("unless key was previously supplied"));
                }
            }

        };


    }

    @Test
    public void testCTRInit8()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
        {
            {

                //
                // wrong key len
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[15]), new byte[8]));
                    fail("invalid iv accepted");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex.getMessage().contains("must be 16,24 or 32 bytes"));
                }
            }

        };


    }


    @Test
    public void testCTRProcessBlock()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
        {
            {
                init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));


                //
                // null input array
                //
                try
                {
                    processBlock(null, 0, new byte[16], 0);
                    fail("accepted null input array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }

                //
                // null output array
                //
                try
                {
                    processBlock(new byte[16], 0, null, 0);
                    fail("accepted null output array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                }

                //
                // negative input offset
                //

                try
                {
                    processBlock(new byte[0], -1, new byte[0], 0);
                    fail("accepted negative in offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input offset was negative"));
                }

                //
                // Negative output offset
                //

                try
                {
                    processBlock(new byte[0], 0, new byte[0], -1);
                    fail("accepted negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output offset was negative"));
                }


                //
                // input buffer too short
                //
                try
                {
                    processBlock(new byte[15], 0, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }


                //
                // input buffer too short for offset
                //
                try
                {
                    processBlock(new byte[16], 1, new byte[0], 0);
                    fail("accepted invalid input");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }


                //
                // Output buffer to short
                //
                try
                {
                    processBlock(new byte[16], 0, new byte[15], 0);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }


                //
                // Output buffer too short for offset
                //
                try
                {
                    processBlock(new byte[16], 0, new byte[16], 1);
                    fail("accepted invalid output");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

        new AESNativeCTR()
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
    public void testCTRProcessBytes()
            throws Exception
    {

        if (skipIt()) {
            return;
        }

        new AESNativeCTR()
        {
            {

                //
                // Null input array
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBytes(null, 0, 1, new byte[16], 0);
                    fail("accepted null input array");
                }
                catch (Throwable ex)
                {
                    assertTrue(ex instanceof NullPointerException);
                    assertTrue(ex.getMessage().contains("input was null"));
                }
            }
        };
        new AESNativeCTR()
        {
            {

                //
                // Negative input offset.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBytes(new byte[0], -1, 1, new byte[0], 0);
                    fail("accepted negative in offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input offset was negative"));
                }
            }
        };
        new AESNativeCTR()
        {
            {
                //
                // Negative block count.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBytes(new byte[0], 0, -1, new byte[0], 0);
                    fail("accepted negative len ");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("len was negative"));
                }
            }
        };
        new AESNativeCTR()
        {
            {
                //
                // Negative output offset
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBytes(new byte[0], 0, 1, new byte[0], -1);
                    fail("accepted negative out offset");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output offset was negative"));
                }
            }
        };
        new AESNativeCTR()
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
                    assertTrue(ex.getMessage().contains("not initialized"));
                }
            }
        };
        new AESNativeCTR()
        {
            {

                //
                // Would attempt to process 16 bytes but offset would put it past
                // end of input array.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBytes(new byte[16], 1, 16, new byte[16], 0);
                    fail("input past end");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input buffer too short"));
                }
            }
        };
        new AESNativeCTR()
        {
            {

                //
                // Would attempt to process 16 bytes but output offset would put it past
                // end of output array.
                //
                try
                {
                    init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                    processBytes(new byte[16], 0, 16, new byte[16], 1);
                    fail("output past end");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output buffer too short"));
                }
            }
        };

        {
            //
            //  Zero length write
            //

            AESNativeCTR engine = new AESNativeCTR();
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in = new byte[16];
            byte[] out = new byte[16];
            TestCase.assertEquals(0, engine.processBytes(in, 16, 0, out, 0));
            TestCase.assertTrue(Arrays.areAllZeroes(out, 0, out.length));

        }

        {
            //
            // Should only write 8 bytes even though there is capacity for 16 in output buffer
            //
            AESNativeCTR engine = new AESNativeCTR();
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in = new byte[16];
            byte[] out = new byte[16];
            TestCase.assertEquals(8, engine.processBytes(in, 8, 8, out, 0));
            TestCase.assertTrue(Arrays.areAllZeroes(out, 8, 8));
        }


        {
            //
            // Should only write 8 bytes because of output offset
            //
            AESNativeCTR engine = new AESNativeCTR();
            engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
            byte[] in = new byte[16];
            byte[] out = new byte[16];
            TestCase.assertEquals(8, engine.processBytes(in, 0, 8, out, 8));
            TestCase.assertTrue(Arrays.areAllZeroes(out, 0, 8));
        }


    }


    @Test
    public void testCTRProcessBlocks()
            throws Exception
    {

        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
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
                    assertTrue(ex.getMessage().contains("input was null"));
                }

            }
        };

        new AESNativeCTR()
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

        new AESNativeCTR()
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
                    assertTrue(ex.getMessage().contains("input offset was negative"));
                }

            }
        };

        new AESNativeCTR()
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
                    // processBlocks is actually fed into processBytes as blocks * blocksSize
                    // therefore len is negative will be the error.
                    assertTrue(ex.getMessage().contains("len was negative") || ex.getMessage().contains("blockCount was negative"));
                }
            }
        };



        new AESNativeCTR()
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
                    assertTrue(ex.getMessage().contains("output offset was negative"));
                }
            }
        };

        new AESNativeCTR()
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

        new AESNativeCTR()
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

        new AESNativeCTR()
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

        new AESNativeCTR()
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

        new AESNativeCTR()
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

        new AESNativeCTR()
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

        new AESNativeCTR()
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

        new AESNativeCTR()
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

        new AESNativeCTR()
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


    @Test
    public void testCTRReference()
    {
        if (skipIt()) {
            return;
        }


        new AESNativeCTR()
        {
            {

                //
                // Valid inputs but not initialised.
                //
                try
                {
                    skip(10);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("not initialized"));
                }
            }
        };

        new AESNativeCTR()
        {
            {

                //
                // Valid inputs but not initialised.
                //
                try
                {
                    seekTo(10);
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("not initialized"));
                }
            }
        };

        new AESNativeCTR()
        {
            {

                //
                // Valid inputs but not initialised.
                //
                try
                {
                    getPosition();
                    fail("not initialized");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("not initialized"));
                }
            }
        };

        new AESNativeCTR()
        {
            {

                //
                // Valid inputs but not initialised.
                //
                try
                {
                    returnByte((byte) 10);
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
