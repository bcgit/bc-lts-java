package org.bouncycastle.cert.test;

import java.io.IOException;

import junit.framework.TestCase;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.cert.ocsp.OCSPResp;

/**
 * Structures too short for their required fields, or with a field too large for the type that reports
 * it, are refused as malformed when parsed - with the IOException the parsing entry points declare -
 * rather than running out of elements or overflowing later.
 */
public class MalformedStructureTest
    extends TestCase
{
    public void testOCSPResponseStatusOutOfRange()
        throws Exception
    {
        // OCSPResponse { responseStatus ENUMERATED 2^40 }, which getStatus() used to fail on with an ArithmeticException
        try
        {
            new OCSPResp(new byte[]{ 0x30, 0x08, 0x0a, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 });
            fail("OCSP response status out of range accepted");
        }
        catch (IOException e)
        {
            assertTrue(e.getMessage().indexOf("invalid OCSP response status") >= 0);
        }
    }

    public void testShortPKIMessage()
        throws Exception
    {
        try
        {
            new GeneralPKIMessage(new byte[]{ 0x30, 0x00 });
            fail("empty PKIMessage accepted");
        }
        catch (CertIOException e)
        {
            assertEquals("malformed data: PKIMessage missing PKIHeader structure", e.getMessage());
        }
        try
        {
            // a PKIMessage whose header holds only pvno
            new GeneralPKIMessage(new byte[]{ 0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x02 });
            fail("short PKIHeader accepted");
        }
        catch (CertIOException e)
        {
            assertEquals("malformed data: bad sequence size: 1", e.getMessage());
        }
    }
}
