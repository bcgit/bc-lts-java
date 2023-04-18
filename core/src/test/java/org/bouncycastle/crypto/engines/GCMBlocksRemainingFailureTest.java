package org.bouncycastle.crypto.engines;


import java.security.Security;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class GCMBlocksRemainingFailureTest
{

    @Before
    public void before()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);

    }

    @Test
    public void testWithOneBlockRemaining_Ok()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_GCM))
        {
            System.out.println("Skipping due to lack of AES/CMUL CPU support.");
            System.out.println("Native Features: "+ TestUtil.getNativeFeatureString());
            return;
        }

        AESNativeGCM gcmEngine = new AESNativeGCM();
        gcmEngine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        gcmEngine.setBlocksRemainingDown((1L << 32) - 3L);

        byte[] scratch = new byte[256];
        byte[] msg = new byte[16];

        //
        // Not expected to fail.
        //
        gcmEngine.processBytes(msg, 0, msg.length, scratch, 0);
        gcmEngine.doFinal(scratch, 0);
    }


    @Test
    public void failWholeBlockExtra()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_GCM))
        {
            System.out.println("Skipping due to lack of AES/CMUL CPU support.");
            System.out.println("Native Features: "+ TestUtil.getNativeFeatureString());
            return;
        }

        AESNativeGCM gcmEngine = new AESNativeGCM();
        gcmEngine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

        byte[] scratch = new byte[256];
        byte[] msg = new byte[16];


        //
        // Expect failure from remaining whole blocks.
        //
        gcmEngine.setBlocksRemainingDown((1L << 32) - 3L);
        gcmEngine.processBytes(msg, 0, msg.length, scratch, 0); // Block 1
        gcmEngine.processBytes(msg, 0, msg.length, scratch, 0); // Block 2
        try
        {
            gcmEngine.doFinal(scratch, 0);
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("attempt to process too many blocks in GCM", ilex.getMessage());
        }

    }


    @Test
    public void failWholeBlockExtraAfterFour()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_GCM))
        {
            System.out.println("Skipping due to lack of AES/CMUL CPU support.");
            System.out.println("Native Features: "+ TestUtil.getNativeFeatureString());
            return;
        }

        AESNativeGCM gcmEngine = new AESNativeGCM();
        gcmEngine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

        byte[] scratch = new byte[256];
        byte[] msg = new byte[16];
        byte[] largeMessage = new byte[64];

        //
        // Expect failure at four block level
        //
        gcmEngine.setBlocksRemainingDown((1L << 32) - 5L);

        try
        {
            gcmEngine.processBytes(largeMessage, 0, largeMessage.length, scratch, 0); // Block 1
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("attempt to process too many blocks in GCM", ilex.getMessage());
        }

    }



    @Test
    public void failDueToPartialFinalBlock()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_GCM))
        {
            System.out.println("Skipping due to lack of AES/CMUL CPU support.");
            System.out.println("Native Features: "+ TestUtil.getNativeFeatureString());
            return;
        }

        AESNativeGCM gcmEngine = new AESNativeGCM();
        gcmEngine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        gcmEngine.setBlocksRemainingDown((1L << 32) - 3L);
        //
        // Expect failure from partial block in do final.
        //

        byte[] longerMessage = new byte[20];
        byte[] scratch = new byte[256];
        gcmEngine.processBytes(longerMessage, 0, longerMessage.length, scratch, 0);
        try
        {
            gcmEngine.doFinal(scratch, 0);
            Assert.fail();
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("attempt to process too many blocks in GCM", ilex.getMessage());
        }
    }

    @Test
    public void testCannotAdjustUp()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_GCM))
        {
            System.out.println("Skipping due to lack of AES/CMUL CPU support.");
            System.out.println("Native Features: "+ TestUtil.getNativeFeatureString());
            return;
        }

        AESNativeGCM gcmEngine = new AESNativeGCM();
        gcmEngine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));
        gcmEngine.setBlocksRemainingDown((1L << 32) - 3L);

        try
        {
            gcmEngine.setBlocksRemainingDown(-10); // Attempt to wind the counter back
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("attempt to increment blocks remaining", ilex.getMessage());
        }
    }

    @Test
    public void testCannotAdjustAfterUse()
        throws Exception
    {
        if (!CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.AES_GCM))
        {
            System.out.println("Skipping due to lack of AES/CMUL CPU support.");
            System.out.println("Native Features: "+ TestUtil.getNativeFeatureString());
            return;
        }

        AESNativeGCM gcmEngine = new AESNativeGCM();
        gcmEngine.init(true, new ParametersWithIV(new KeyParameter(new byte[16]), new byte[16]));

        byte[] scratch = new byte[256];
        gcmEngine.processByte((byte)10, scratch, 0);

        try
        {
            gcmEngine.setBlocksRemainingDown(1); // Attempt after use
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("data has been written", ilex.getMessage());
        }
    }


}
