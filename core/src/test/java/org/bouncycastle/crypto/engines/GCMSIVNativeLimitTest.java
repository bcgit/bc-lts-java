package org.bouncycastle.crypto.engines;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.junit.Test;

public class GCMSIVNativeLimitTest extends TestCase
{

    @Test
    public void testInitNative()
    throws Exception
    {
        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }


        // Invalid key sizes
        new AESNativeGCMSIV()
        {
            {
                for (int size : new int[]{15, 17, 24, 31, 33})
                {
                    long ref = makeInstance();
                    try
                    {
                        initNative(ref, true, new byte[size], new byte[12], null);
                        fail("invalid key size");
                    }
                    catch (Exception ex)
                    {
                        assertTrue(ex.getMessage().contains("key must be only 16, or 32 bytes long"));
                    }
                    finally
                    {
                        dispose(ref);
                    }
                }
            }
        };


        // null key
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, null, new byte[12], null);
                    fail("invalid key size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("key was null"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

        // Invalid nonce sizes
        new AESNativeGCMSIV()
        {
            {
                for (int size : new int[]{11, 13})
                {
                    long ref = makeInstance();
                    try
                    {
                        initNative(ref, true, new byte[16], new byte[size], null);
                        fail("invalid key size");
                    }
                    catch (Exception ex)
                    {
                        assertTrue(ex.getMessage().contains("iv must be 12 bytes"));
                    }
                    finally
                    {
                        dispose(ref);
                    }
                }
            }
        };

        //
        // Null iv
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], null, null);
                    fail("invalid key size");
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("iv was null"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };


        // valid key sizes, nonce can only be 12 bytes.
        new AESNativeGCMSIV()
        {
            {
                for (int size : new int[]{16, 32})
                {
                    long ref = makeInstance();
                    try
                    {
                        initNative(ref, true, new byte[size], new byte[12], null);
                    }
                    finally
                    {
                        dispose(ref);
                    }
                }
            }
        };

        // valid input with optional aad
        new AESNativeGCMSIV()
        {
            {
                for (int size : new int[]{16, 32})
                {
                    long ref = makeInstance();
                    try
                    {
                        initNative(ref, true, new byte[size], new byte[12], new byte[0]);
                    }
                    finally
                    {
                        dispose(ref);
                    }
                }
            }
        };

    }

    @Test
    public void testUpdateAADBytes()
    throws Exception
    {

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }


        //
        // Null aad
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    processAADBytes(ref, null, 0, 0);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("aad was null"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

        //
        // negative offset
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    processAADBytes(ref, new byte[0], -1, 0);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("offset is negative"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

        //
        // negative len
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    processAADBytes(ref, new byte[0], 0, -1);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("len is negative"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

        //
        // past end of array
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    processAADBytes(ref, new byte[1], 1, 1);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("array too short for offset + len"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

        //
        // past end of array
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    processAADBytes(ref, new byte[1], 0, 2);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("array too short for offset + len"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

        //
        // past end of array
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    processAADBytes(ref, new byte[0], 0, 1);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("array too short for offset + len"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

        //
        // Check checkAEADStatus trips
        //
        new AESNativeGCMSIV()
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    processAADBytes(ref, new byte[3], 0, 3);
                    test_set_max_dl(ref, 3);

                    //
                    // Should fail as no more can be included in hash
                    //
                    processAADBytes(ref, new byte[1], 0, 1);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("AEAD byte count exceeded"));
                }
                finally
                {
                    dispose(ref);
                }
            }
        };

    }


    @Test
    public void testDoFinal()
    throws Exception
    {

        if (!isNativeVariant())
        {
            System.out.println("Skipping as native is not available");
            return;
        }

        new AESNativeGCMSIV() // input was null
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, null, 0, new byte[1], 1);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("input was null"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };

        new AESNativeGCMSIV() // input len is negative
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[1], -1, new byte[1], 1);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("input len is negative"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // input len past end of buffer
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[1], 2, new byte[1], 1);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("input too short for length"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };

        new AESNativeGCMSIV() // input exceeds byte count
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    test_set_max_dl(ref, 2);
                    doFinal(ref, new byte[3], 3, new byte[1], 1);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("byte count exceeded"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // input passes checkStatus
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    test_set_max_dl(ref, 2);
                    doFinal(ref, new byte[3], 2, new byte[32], 0);
                }
                finally
                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // output null
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[3], 3, null, 0);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("output was null"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // negative out offset
        {
            {
                long ref = makeInstance();
                try
                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[3], 3, new byte[0], -1);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("offset is negative"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };

        new AESNativeGCMSIV() // offset past end of array
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[3], 3, new byte[0], 1);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("offset past end of array"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // too short encryption
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[1], 1, new byte[0], 0);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("output at offset too short"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };

        new AESNativeGCMSIV() // too short encryption
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[1], 1, new byte[1], 1);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("output at offset too short"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };

        new AESNativeGCMSIV() // too short encryption
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, true, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[2], 2, new byte[1], 0);
                    fail();
                }
                catch (Exception ex)

                {
                    assertTrue(ex.getMessage().contains("output at offset too short"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // input too short < tag len
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, false, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[15], 15, new byte[1], 1);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("input less than tag len"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // too short decryption
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, false, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[17], 17, new byte[0], 0);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output at offset too short"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };

        new AESNativeGCMSIV() // too short decryption
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, false, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[18], 18, new byte[1], 0);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output at offset too short"));
                }
                finally

                {
                    dispose(ref);
                }
            }
        };


        new AESNativeGCMSIV() // too short decryption
        {
            {
                long ref = makeInstance();
                try

                {
                    initNative(ref, false, new byte[16], new byte[12], null);
                    doFinal(ref, new byte[18], 18, new byte[2], 1);
                    fail();
                }
                catch (Exception ex)
                {
                    assertTrue(ex.getMessage().contains("output at offset too short"));
                }
                finally

                {
                    dispose(ref);
                }
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
        return CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCMSIV);
    }
}
