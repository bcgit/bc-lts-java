package org.bouncycastle.math;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.NativeServices;
import org.bouncycastle.math.raw.Mul;
import org.junit.Test;

public class MulLimitTest
{

    private boolean skip()
    {
        return !CryptoServicesRegistrar.getNativeServices().hasService(NativeServices.MULACC);
    }


    @Test
    public void testXNotNull() throws Exception
    {

        if (skip())
        {
            return;
        }

        try
        {
            Mul.multiplyAcc(null, 0, new long[0], 0, new long[0]);
            TestCase.fail();
        }
        catch (NullPointerException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("x array is null"));
        }
    }

    @Test
    public void testYNotNull() throws Exception
    {

        if (skip())
        {
            return;
        }

        try
        {
            Mul.multiplyAcc(new long[0], 0, null, 0, new long[0]);
            TestCase.fail();
        }
        catch (NullPointerException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("y array is null"));
        }
    }

    @Test
    public void testZNotNull() throws Exception
    {

        if (skip())
        {
            return;
        }

        try
        {
            Mul.multiplyAcc(new long[0], 0, new long[0], 0, null);
            TestCase.fail();
        }
        catch (NullPointerException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("z array is null"));
        }
    }

    @Test
    public void testXOffNeg() throws Exception
    {
        if (skip())
        {
            return;
        }

        try
        {
            Mul.multiplyAcc(new long[0], -1, new long[0], 0, new long[2]);
            TestCase.fail();
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("x offset is negative"));
        }
    }


    @Test
    public void testYOffNeg() throws Exception
    {
        if (skip())
        {
            return;
        }

        try
        {
            Mul.multiplyAcc(new long[0], 0, new long[0], -1, new long[2]);
            TestCase.fail();
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("y offset is negative"));
        }
    }


    @Test
    public void testXOffPastEnd() throws Exception
    {
        if (skip())
        {
            return;
        }

        try
        {
            Mul.multiplyAcc(new long[1], 2, new long[0], 0, new long[2]);
            TestCase.fail();
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("x offset is past end of array"));
        }
    }


    @Test
    public void testYOffPastEnd() throws Exception
    {
        if (skip())
        {
            return;
        }

        try
        {
            Mul.multiplyAcc(new long[1], 0, new long[0], 1, new long[2]);
            TestCase.fail();
        }
        catch (IllegalArgumentException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("y offset is past end of array"));
        }
    }


    @Test
    public void testXYSameSize() throws Exception
    {
        if (skip())
        {
            return;
        }


        //
        // Zero offset
        //
        try
        {
            Mul.multiplyAcc(new long[1], 0, new long[0], 0, new long[2]);
            TestCase.fail();
        }
        catch (IllegalStateException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("x,y are not the same size"));
        }

        // x with offset makes size the same
        Mul.multiplyAcc(new long[2], 1, new long[1], 0, new long[2]);

        // y with offset makes size the same
        Mul.multiplyAcc(new long[1], 0, new long[2], 1, new long[2]);


        // x offset makes size different
        try
        {
            Mul.multiplyAcc(new long[2], 1, new long[2], 0, new long[2]);
            TestCase.fail();
        }
        catch (IllegalStateException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("x,y are not the same size"));
        }


        // y offset makes size different
        try
        {
            Mul.multiplyAcc(new long[2], 0, new long[2], 1, new long[2]);
            TestCase.fail();
        }
        catch (IllegalStateException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("x,y are not the same size"));
        }


    }


    @Test
    public void testZSizeRange() throws Exception
    {
        if (skip())
        {
            return;
        }

        // Note:
        // x len is asserted to be y len accounting for offsets.
        // z len must not be < 2 * x len


        //
        // Ok as 2 x 2 = 4;
        //
        Mul.multiplyAcc(new long[2], 0, new long[2], 0, new long[4]);

        //
        // Ok as 5 > 2 x 2
        //
        Mul.multiplyAcc(new long[2], 0, new long[2], 0, new long[5]);


        // NB size after offset assertions are done in other tests


        // Bad because 3 < 2 x 2
        try
        {
            Mul.multiplyAcc(new long[2], 0, new long[2], 0, new long[3]);

            TestCase.fail();
        }
        catch (IllegalStateException ex)
        {
            TestCase.assertTrue(ex.getMessage().contains("z is less than twice the size of x"));
        }


    }


}
