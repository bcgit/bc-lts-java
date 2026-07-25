package org.bouncycastle.cms.test;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.cms.GCMParameters;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * Pins the contract of {@code CMSUtils.getAEADMacLength}, which decides the tag length a recipient
 * checks against its configured minimum.
 * <p>
 * The distinction that matters is what happens when the AEAD parameters are unusable. They come off
 * the wire on a decrypt and are therefore attacker-controlled, and the method must not report
 * "no opinion" for them: returning a negative value makes
 * {@code AbstractRecipient.checkTagSize} skip its {@code macLenOctets >= 0} branch entirely, so a
 * message with no parameters at all would sail past a configured minimum tag size. Reporting a
 * zero-length MAC instead means the floor rejects it - fail-closed.
 * <p>
 * {@code getAEADMacLength} is package-private in {@code org.bouncycastle.cms}, so it is reached here
 * by reflection rather than by moving the test out of this package.
 */
public class AEADMacLengthTest
    extends TestCase
{
    private static Method getAEADMacLength()
        throws Exception
    {
        Method m = Class.forName("org.bouncycastle.cms.CMSUtils")
            .getDeclaredMethod("getAEADMacLength", AlgorithmIdentifier.class);
        m.setAccessible(true);

        return m;
    }

    private static int call(AlgorithmIdentifier algId)
        throws Exception
    {
        try
        {
            return ((Integer)getAEADMacLength().invoke(null, algId)).intValue();
        }
        catch (InvocationTargetException e)
        {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException)
            {
                fail("getAEADMacLength leaked " + cause.getClass().getName() + ": " + cause.getMessage());
            }
            throw e;
        }
    }

    public void testWellFormedGcmReportsItsIcvLength()
        throws Exception
    {
        int icvLen = 12;
        AlgorithmIdentifier algId = new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_GCM,
            new GCMParameters(new byte[12], icvLen));

        assertEquals(icvLen, call(algId));
    }

    /**
     * The case the fail-closed behaviour exists for: a GCM content algorithm with the parameters
     * omitted entirely. Must be zero, not negative - a negative result is treated as "unknown" and
     * skips the minimum-tag-size check.
     */
    public void testAbsentGcmParametersReportZeroNotUnknown()
        throws Exception
    {
        int macLen = call(new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_GCM));

        assertEquals("absent AEAD parameters must report a zero-length MAC so a minimum-tag-size "
            + "floor rejects the message, not a negative 'unknown' that skips the check", 0, macLen);
    }

    public void testMalformedGcmParametersReportZero()
        throws Exception
    {
        // an ICV length GCMParameters' own validation rejects
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new DEROctetString(new byte[12]));
        v.add(new ASN1Integer(-1));

        assertEquals(0, call(new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_GCM, new DERSequence(v))));
    }

    public void testWrongShapedGcmParametersReportZero()
        throws Exception
    {
        // parameters present but not a GCMParameters SEQUENCE at all
        assertEquals(0, call(new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_GCM, DERNull.INSTANCE)));
    }

    /**
     * A non-AEAD algorithm genuinely has no AEAD tag length, and -1 is the right answer there: the
     * minimum-tag-size check does not apply to it.
     */
    public void testNonAeadAlgorithmReportsUnknown()
        throws Exception
    {
        assertEquals(-1, call(new AlgorithmIdentifier(NISTObjectIdentifiers.id_aes128_CBC, new DEROctetString(new byte[16]))));
    }
}
