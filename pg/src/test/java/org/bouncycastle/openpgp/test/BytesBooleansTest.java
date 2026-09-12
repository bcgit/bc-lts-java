package org.bouncycastle.openpgp.test;

import org.bouncycastle.bcpg.sig.PrimaryUserID;

import junit.framework.TestCase;

public class BytesBooleansTest
    extends TestCase
{
    public void testParseFalse()
    {
        PrimaryUserID primaryUserID = new PrimaryUserID(true, false);

        byte[] bFalse = primaryUserID.getData();
        assertEquals(1, bFalse.length);
        assertEquals(0, bFalse[0]);
        assertFalse(primaryUserID.isPrimaryUserID());
    }

    public void testParseTrue()
    {
        PrimaryUserID primaryUserID = new PrimaryUserID(true, true);

        byte[] bTrue = primaryUserID.getData();

        assertEquals(1, bTrue.length);
        assertEquals(1, bTrue[0]);
        assertTrue(primaryUserID.isPrimaryUserID());
    }

    public void testParseTooShort()
    {
        try
        {
            new PrimaryUserID(true, false, new byte[0]);
            fail("Should throw.");
        }
        catch (IllegalArgumentException e)
        {
            // expected - RFC 9580 sec. 5.2.3.27 defines the body as a single octet.
        }
    }

    public void testParseTooLong()
    {
        try
        {
            new PrimaryUserID(true, false, new byte[42]);
            fail("Should throw.");
        }
        catch (IllegalArgumentException e)
        {
            // expected.
        }
    }

    public void testParseIllegalValue()
    {
        try
        {
            new PrimaryUserID(true, false, new byte[]{ 2 });
            fail("Should throw.");
        }
        catch (IllegalArgumentException e)
        {
            // expected - the flag octet is a zero or a one.
        }
    }
}
