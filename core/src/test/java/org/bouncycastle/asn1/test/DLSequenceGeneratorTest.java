package org.bouncycastle.asn1.test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DLSequence;
import org.bouncycastle.asn1.DLSequenceGenerator;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

/**
 * {@link DLSequenceGenerator} streams a definite-length SEQUENCE whose body length is declared
 * before any content is written - the point being that nothing is buffered, so the body may exceed
 * the size of a Java array.
 * <p>
 * The declared length is therefore load-bearing: it is written into the header before the caller
 * produces a single content octet, so if the caller's arithmetic is wrong the output is already
 * unusable by the time anything notices. Both directions of that mistake have to be caught rather
 * than emitted, which is most of what is tested here.
 */
public class DLSequenceGeneratorTest
    extends SimpleTest
{
    public String getName()
    {
        return "DLSequenceGenerator";
    }

    public void performTest()
        throws Exception
    {
        checkMatchesOneShotEncoding();
        checkTaggedMatchesOneShotEncoding();
        checkUnderWriteRejected();
        checkOverWriteRejected();
        checkRawStreamCounted();
    }

    /**
     * The streamed encoding must be byte-identical to building the same SEQUENCE in memory and
     * encoding it DL - otherwise the two routes disagree about the wire format.
     */
    private void checkMatchesOneShotEncoding()
        throws IOException
    {
        ASN1Integer one = new ASN1Integer(1);
        ASN1Integer two = new ASN1Integer(2);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLSequenceGenerator gen = new DLSequenceGenerator(bOut, bodyLength(one, two));
        gen.addObject(one);
        gen.addObject(two);
        gen.close();

        byte[] streamed = bOut.toByteArray();
        byte[] oneShot = new DLSequence(new ASN1Encodable[]{one, two}).getEncoded(ASN1Encoding.DL);

        if (!Arrays.areEqual(oneShot, streamed))
        {
            fail("streamed DL SEQUENCE does not match the one-shot encoding");
        }

        // definite length, i.e. not the BER indefinite-length marker
        if ((streamed[1] & 0xff) == 0x80)
        {
            fail("generator emitted an indefinite-length header");
        }
    }

    private void checkTaggedMatchesOneShotEncoding()
        throws IOException
    {
        ASN1Integer one = new ASN1Integer(7);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLSequenceGenerator gen = new DLSequenceGenerator(bOut, 1, true, bodyLength(one));
        gen.addObject(one);
        gen.close();

        byte[] streamed = bOut.toByteArray();
        byte[] oneShot = new org.bouncycastle.asn1.DERTaggedObject(true, 1,
            new DLSequence(one)).getEncoded(ASN1Encoding.DL);

        if (!Arrays.areEqual(oneShot, streamed))
        {
            fail("streamed tagged DL SEQUENCE does not match the one-shot encoding");
        }
    }

    /**
     * Declaring more than is written leaves a truncated SEQUENCE on the wire. close() must refuse.
     */
    private void checkUnderWriteRejected()
        throws IOException
    {
        ASN1Integer one = new ASN1Integer(1);
        ASN1Integer two = new ASN1Integer(2);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLSequenceGenerator gen = new DLSequenceGenerator(bOut, bodyLength(one, two));
        gen.addObject(one);

        try
        {
            gen.close();
            fail("close() accepted a body shorter than the declared length");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    /**
     * Declaring less than is written would overrun into whatever follows. That must fail at the
     * write, not at close, so no invalid octets reach the target stream.
     */
    private void checkOverWriteRejected()
        throws IOException
    {
        ASN1Integer one = new ASN1Integer(1);
        ASN1Integer two = new ASN1Integer(2);

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLSequenceGenerator gen = new DLSequenceGenerator(bOut, bodyLength(one));
        gen.addObject(one);

        try
        {
            gen.addObject(two);
            fail("generator accepted content past the declared length");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    /**
     * Raw writes go through the same counter as addObject, so a caller streaming octets directly is
     * bounded identically.
     */
    private void checkRawStreamCounted()
        throws IOException
    {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DLSequenceGenerator gen = new DLSequenceGenerator(bOut, 3);
        OutputStream body = gen.getRawOutputStream();

        body.write(new byte[]{1, 2, 3});

        try
        {
            body.write(4);
            fail("raw body stream accepted content past the declared length");
        }
        catch (IOException e)
        {
            // expected
        }
    }

    private static long bodyLength(ASN1Encodable... objects)
        throws IOException
    {
        long total = 0;
        for (int i = 0; i != objects.length; i++)
        {
            total += objects[i].toASN1Primitive().getEncoded(ASN1Encoding.DL).length;
        }

        return total;
    }

    public static void main(String[] args)
    {
        runTest(new DLSequenceGeneratorTest());
    }
}
