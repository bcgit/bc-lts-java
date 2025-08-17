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
import org.bouncycastle.operator.DigestAlgorithmIdentifierFinder;

/**
 * Generator for RFC 3161 Time Stamp Request objects.
 */
public class TimeStampRequestGenerator
{
    private static final DefaultDigestAlgorithmIdentifierFinder DEFAULT_DIGEST_ALG_FINDER =
        new DefaultDigestAlgorithmIdentifierFinder();

    private final ExtensionsGenerator extGenerator = new ExtensionsGenerator();

    private final DigestAlgorithmIdentifierFinder digestAlgFinder;

    private ASN1ObjectIdentifier reqPolicy;
    private ASN1Boolean certReq;

    public TimeStampRequestGenerator()
    {
        this(DEFAULT_DIGEST_ALG_FINDER);
    }

    public TimeStampRequestGenerator(DigestAlgorithmIdentifierFinder digestAlgFinder)
    {
        if (digestAlgFinder == null)
        {
            throw new NullPointerException("'digestAlgFinder' cannot be null");
        }

        this.digestAlgFinder = digestAlgFinder;
    }

    public void setReqPolicy(ASN1ObjectIdentifier reqPolicy)
    {
        this.reqPolicy = reqPolicy;
    }

    public void setCertReq(ASN1Boolean certReq)
    {
        this.certReq = certReq;
    }

    public void setCertReq(boolean certReq)
    {
        setCertReq(ASN1Boolean.getInstance(certReq));
    }

    /**
     * add a given extension field for the standard extensions tag (tag 3)
     * @throws TSPIOException
     */
    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, ASN1Encodable value) throws TSPIOException
    {
        TSPUtil.addExtension(extGenerator, oid, isCritical, value);
    }

    /**
     * add a given extension field for the standard extensions tag
     * The value parameter becomes the contents of the octet string associated
     * with the extension.
     */
    public void addExtension(ASN1ObjectIdentifier oid, boolean isCritical, byte[] value)
    {
        extGenerator.addExtension(oid, isCritical, value);
    }

    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest)
    {
        return generate(digestAlgorithm, digest, null);
    }

    public TimeStampRequest generate(ASN1ObjectIdentifier digestAlgorithm, byte[] digest, BigInteger nonce)
    {
        return generate(digestAlgFinder.find(digestAlgorithm), digest, nonce);
    }

    public TimeStampRequest generate(AlgorithmIdentifier digestAlgorithmID, byte[] digest)
    {
        return generate(digestAlgorithmID, digest, null);
    }

    public TimeStampRequest generate(AlgorithmIdentifier digestAlgorithmID, byte[] digest, BigInteger nonce)
    {
        if (digestAlgorithmID == null)
        {
            throw new NullPointerException("'digestAlgorithmID' cannot be null");
        }

        MessageImprint messageImprint = new MessageImprint(digestAlgorithmID, digest);
        ASN1Integer reqNonce = nonce == null ? null : new ASN1Integer(nonce);
        Extensions ext = extGenerator.isEmpty() ? null : extGenerator.generate();

        return new TimeStampRequest(new TimeStampReq(messageImprint, reqPolicy, reqNonce, certReq, ext));
    }
}
