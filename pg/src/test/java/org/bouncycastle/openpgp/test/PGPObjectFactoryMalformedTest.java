package org.bouncycastle.openpgp.test;

import java.io.IOException;

import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.bc.BcPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.SimpleTest;

/**
 * {@link PGPObjectFactory#nextObject()} declares only IOException, but a packet sequence the objects built
 * from it refuse - here a v4 SKESK before a v2 SEIPD, which RFC 9580 sec. 5.3 forbids - used to escape it
 * as an unchecked IllegalArgumentException. It is now an IOException with that as the cause.
 */
public class PGPObjectFactoryMalformedTest
    extends SimpleTest
{
    // v4 SKESK (AES-256, simple S2K, SHA-256), then a v2 SEIPD (AES-256, OCB, chunk size 6, zero salt)
    private static final String V4_SKESK_BEFORE_V2_SEIPD = "c30404090008" + "d23402090206"
        + "0000000000000000000000000000000000000000000000000000000000000000" + "00000000000000000000000000000000";

    public String getName()
    {
        return "PGPObjectFactoryMalformedTest";
    }

    public void performTest()
        throws Exception
    {
        byte[] encoding = Hex.decode(V4_SKESK_BEFORE_V2_SEIPD);

        check(new BcPGPObjectFactory(encoding));
        check(new JcaPGPObjectFactory(encoding));
    }

    private void check(PGPObjectFactory factory)
    {
        try
        {
            factory.nextObject();
            fail("nextObject() accepted a v4 SKESK before a v2 SEIPD");
        }
        catch (IOException e)
        {
            isTrue("cause", e.getCause() instanceof IllegalArgumentException);
        }
        catch (RuntimeException e)
        {
            fail("nextObject() threw unchecked " + e, e);
        }
    }

    public static void main(String[] args)
    {
        runTest(new PGPObjectFactoryMalformedTest());
    }
}
