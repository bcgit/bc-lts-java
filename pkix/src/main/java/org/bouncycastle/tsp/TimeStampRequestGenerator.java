package org.bouncycastle.tsp;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.tsp.MessageImprint;
import org.bouncycastle.asn1.tsp.TimeStampReq;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;

/**
 * Generator for RFC 3161 Time Stamp Request objects.
 */
public class TimeStampRequestGenerator
{
    private static final DefaultDigestAlgorithmIdentifierFinder dgstAlgFinder = new DefaultDigestAlgorithmIdentifierFinder();

    private ASN1ObjectIdentifier reqPolicy;

    private ASN1Boolean certReq;
    private ExtensionsGenerator extGenerator = new ExtensionsGenerator();

    public TimeStampRequestGenerator()
    {
    }

    public void setReqPolicy(
        ASN1ObjectIdentifier reqPolicy)
    {
        this.reqPolicy= reqPolicy;
    }

    public void setCertReq(
        boolean certReq)
    {
        this.certReq = ASN1Boolean.getInstance(certReq);
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * @throws TSPIOException
     */
    public void addExtension(
        ASN1ObjectIdentifier oid,
        boolean              isCritical,
        ASN1Encodable        value)
        throws TSPIOException
    {
        TSPUtil.addExtension(extGenerator, oid, isCritical, value);
    }

    /**
     * add a given extension field for the standard extensions tag
     * The value parameter becomes the contents of the octet string associated
     * with the extension.
     */
    public void addExtension(
        ASN1ObjectIdentifier oid,
        boolean              isCritical,
        byte[]               value)
    {
        extGenerator.addExtension(oid, isCritical, value);
    }

    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest)
    {
        return generate(dgstAlgFinder.find(digestAlgorithm), digest);
    }

    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, BigInteger nonce)
    {
        return generate(dgstAlgFinder.find(digestAlgorithm), digest, nonce);
    }

    public TimeStampRequest generate(
        AlgorithmIdentifier     digestAlgorithmID,
        byte[]                  digest)
    {
        return generate(digestAlgorithmID, digest, null);
    }

    public TimeStampRequest generate(
        AlgorithmIdentifier     digestAlgorithmID,
        byte[]                  digest,
        BigInteger              nonce)
    {
        if (digestAlgorithmID == null)
        {
            throw new IllegalArgumentException("digest algorithm not specified");
        }

        MessageImprint messageImprint = new MessageImprint(digestAlgorithmID, digest);

        Extensions  ext = null;

        if (!extGenerator.isEmpty())
        {
            ext = extGenerator.generate();
        }

        if (nonce != null)
        {
            return new TimeStampRequest(new TimeStampReq(messageImprint,
                    reqPolicy, new ASN1Integer(nonce), certReq, ext));
        }
        else
        {
            return new TimeStampRequest(new TimeStampReq(messageImprint,
                    reqPolicy, null, certReq, ext));
        }
    }
}
