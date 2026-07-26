package org.bouncycastle.crypto.engines;




import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;


public class GCMBlocksRemainingFailureTest extends TestCase
{

    @Before
    public void setUp()
    {
        CryptoServicesRegistrar.setNativeEnabled(true);

    }

    @Test
    public void testWithOneBlockRemaining_Ok()
        throws Exception
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
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
    public void testFailWholeBlockExtra()
        throws Exception
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
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
        // The feed is inside the try because the throw point is implementation dependent: a wide
        // implementation buffers these blocks and accounts for them in doFinal, a narrower one can
        // reject them in processBytes. Either is acceptable, silence is not.
        gcmEngine.setBlocksRemainingDown((1L << 32) - 3L);
        try
        {
            gcmEngine.processBytes(msg, 0, msg.length, scratch, 0); // Block 1
            gcmEngine.processBytes(msg, 0, msg.length, scratch, 0); // Block 2
            gcmEngine.doFinal(scratch, 0);
            Assert.fail("processing past the GCM block limit did not throw");
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("attempt to process too many blocks in GCM", ilex.getMessage());
        }

    }


    @Test
    public void testFailWholeBlockExtraAfterFour()
        throws Exception
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
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
        // Expect failure from the four blocks of largeMessage exceeding the three remaining.
        //
        // Which call reports it is implementation dependent and must not be asserted: the 128 bit
        // wide path (avx, vaes) checks in units of four blocks and rejects this inside processBytes,
        // while the 512 bit wide path (vaesf) checks in units of sixteen, buffers the four blocks
        // and only accounts for them per block in doFinal. Requiring the pair to throw pins the
        // property that matters - the limit is enforced - without pinning where.
        //
        gcmEngine.setBlocksRemainingDown((1L << 32) - 5L);

        try
        {
            gcmEngine.processBytes(largeMessage, 0, largeMessage.length, scratch, 0);
            gcmEngine.doFinal(scratch, 0);
            Assert.fail("processing past the GCM block limit did not throw");
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("attempt to process too many blocks in GCM", ilex.getMessage());
        }

    }



    @Test
    public void testFailDueToPartialFinalBlock()
        throws Exception
    {
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
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
        try
        {
            gcmEngine.processBytes(longerMessage, 0, longerMessage.length, scratch, 0);
            gcmEngine.doFinal(scratch, 0);
            Assert.fail("processing a partial final block past the limit did not throw");
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
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
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
            Assert.fail("winding the blocks-remaining counter back did not throw");
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
        if (!CryptoServicesRegistrar.hasEnabledService(NativeServices.AES_GCM))
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
            Assert.fail("adjusting blocks remaining after use did not throw");
        }
        catch (IllegalArgumentException ilex)
        {
            Assert.assertEquals("data has been written", ilex.getMessage());
        }
    }


}
