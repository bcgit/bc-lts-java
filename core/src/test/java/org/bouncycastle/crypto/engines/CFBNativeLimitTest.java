package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;

import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.junit.Before;
import org.junit.Test;

public class CFBNativeLimitTest extends TestCase
{
    @Before
    public void setUp()
    {
//        FipsStatus.isReady();
//        NativeLoader.setNativeEnabled(true);
    }

    @Test
    public void testCFBInit()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native cfb and no skip set for it");
                return;
            }
            System.out.println("Skipping CFB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }
        // native method calls

        new AESNativeCFB()
        {
            {
                long ref = makeNative(true, 16);
                try
                {
                    init(ref, null, new byte[16]);
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

        new AESNativeCFB()
        {
            {
                long ref = makeNative(true, 16);
                try
                {
                    init(ref, new byte[16], null);
                    dispose(ref);
                    fail("accepted null iv");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof NullPointerException);
                    TestCase.assertTrue(ex.getMessage().contains("iv is null"));
                }
                dispose(ref);
            }
        };


        new AESNativeCFB()
        {
            {
                long ref = makeNative(true, 16);
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


        new AESNativeCFB()
        {
            {
                long ref = makeNative(true, 16);
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



        new AESNativeCFB()
        {
            {
                long ref = 0;
                try
                {
                    ref = makeNative(true, 15);
                    dispose(ref);
                    fail("accepted invalid key len in makeNative");
                }
                catch (Exception ex)
                {
                    TestCase.assertTrue(ex instanceof IllegalArgumentException);
                    TestCase.assertTrue(ex.getMessage().contains("key must be only 16,24 or 32 bytes long"));
                }
            }
        };


        // -- end native method calls


        try
        { // Test incorrect feedback block size.
            new AESNativeCFB(127);
        }
        catch (Exception ex)
        {
            assertTrue(ex.getMessage().contains("can only be 128"));
        }

        new AESNativeCFB()
        {
            { // Should pass because block size IVs are padded.
                ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[10]);
                init(true, piv);
            }
        };


        new AESNativeCFB()
        {
            {


                //
                // Passing null iv causes some failure.
                //
                try
                {
                    init(false, new KeyParameter(new byte[16]));
                    fail("accepted null iv");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("iv is null"));
                }
            }
        };

        new AESNativeCFB()
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

            }
        };

        new AESNativeCFB()
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
                    }, new byte[16]);
                    init(true, piv);
                    fail("accepted null key");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("cannot change encrypting state without providing key"));
                }

            }
        };

        new AESNativeCFB()
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
                    assertTrue(ex.getMessage().contains("between one and block size length"));
                }

            }
        };

        new AESNativeCFB()
        {
            {
                //
                // Pass invalid iv size
                //
                try
                {
                    ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[17]);
                    init(true, piv);
                    fail("accepted invalid iv size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("between one and block size length"));
                }

            }
        };

        new AESNativeCFB()
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

            }
        };

        new AESNativeCFB()
        {
            {

                //
                // Key changing
                //

                ParametersWithIV piv = new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]);
                init(true, piv);
                init(true, new KeyParameter(new byte[16]));


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
    public void testCFBProcessBlock()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native cfb and no skip set for it");
                return;
            }
            System.out.println("Skipping CFB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }

        new AESNativeCFB()
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
                    assertTrue(ex.getMessage().contains("input was null"));
                }

            }
        };
        new AESNativeCFB()
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
                    assertTrue(ex.getMessage().contains("output was null"));
                }
            }
        };
        new AESNativeCFB()
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
                    assertTrue(ex.getMessage().contains("input offset was negative"));
                }
            }
        };
        new AESNativeCFB()
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
                    assertTrue(ex.getMessage().contains("output offset was negative"));
                }
            }
        };
        new AESNativeCFB()
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
        new AESNativeCFB()
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
        new AESNativeCFB()
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
        new AESNativeCFB()
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
        new AESNativeCFB()
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
    public void testCFBProcessBytes()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native cfb and no skip set for it");
                return;
            }
            System.out.println("Skipping CFB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

            {
                //
                //  Zero length write
                //

                AESNativeCFB engine = new AESNativeCFB();
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
                AESNativeCFB engine = new AESNativeCFB();
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
                AESNativeCFB engine = new AESNativeCFB();
                engine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
                byte[] in = new byte[16];
                byte[] out = new byte[16];
                TestCase.assertEquals(8, engine.processBytes(in, 0, 8, out, 8));
                TestCase.assertTrue(Arrays.areAllZeroes(out, 0, 8));
            }


        };
    }


    @Test
    public void testCFBProcessBlocks()
            throws Exception
    {

        NativeServices nativeServices = CryptoServicesRegistrar.getNativeServices();
        if (!nativeServices.hasService("AES/CFB"))
        {
            if (!System.getProperty("test.bcfips.ignore.native","").contains("cbc"))
            {
                fail("no native cfb and no skip set for it");
                return;
            }
            System.out.println("Skipping CFB native limit test: " + CryptoServicesRegistrar.isNativeEnabled());
            return;
        }

        new AESNativeCFB()
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

        new AESNativeCFB()
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
                    assertTrue(ex.getMessage().contains("output was null"));
                }
            }
        };

        new AESNativeCFB()
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

        new AESNativeCFB()
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
                    assertTrue(ex.getMessage().contains("len was negative") || ex.getMessage().contains("blockCount is negative"));
                }
            }
        };

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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

        new AESNativeCFB()
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
