package org.bouncycastle.mozilla;

import java.io.IOException;
import java.io.OutputStream;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.mozilla.PublicKeyAndChallenge;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Encodable;

/**
 * This is designed to parse the SignedPublicKeyAndChallenge created by the
 * KEYGEN tag included by Mozilla based browsers.
 *  <pre>
 *  PublicKeyAndChallenge ::= SEQUENCE {
 *    spki SubjectPublicKeyInfo,
 *    challenge IA5STRING
 *  }
 *
 *  SignedPublicKeyAndChallenge ::= SEQUENCE {
 *    publicKeyAndChallenge PublicKeyAndChallenge,
 *    signatureAlgorithm AlgorithmIdentifier,
 *    signature BIT STRING
 *  }
 *  </pre>
 */
public class SignedPublicKeyAndChallenge
    implements Encodable
{
    protected final org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge          spkacSeq;

    public SignedPublicKeyAndChallenge(byte[] bytes)
    {
        spkacSeq = org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge.getInstance(bytes);
    }

    protected SignedPublicKeyAndChallenge(org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge struct)
    {
        this.spkacSeq = struct;
    }

    /**
     * Return the underlying ASN.1 structure for this challenge.
     *
     * @return a SignedPublicKeyAndChallenge object.
     */
    public org.bouncycastle.asn1.mozilla.SignedPublicKeyAndChallenge toASN1Structure()
    {
         return spkacSeq;
    }

    public PublicKeyAndChallenge getPublicKeyAndChallenge()
    {
        return spkacSeq.getPublicKeyAndChallenge();
    }

    public boolean isSignatureValid(ContentVerifierProvider verifierProvider)
        throws OperatorCreationException, IOException
    {
        ContentVerifier verifier = verifierProvider.get(spkacSeq.getSignatureAlgorithm());

        OutputStream sOut = verifier.getOutputStream();
        spkacSeq.getPublicKeyAndChallenge().encodeTo(sOut, ASN1Encoding.DER);
        sOut.close();

        return verifier.verify(spkacSeq.getSignature().getOctets());
    }

    public SubjectPublicKeyInfo getSubjectPublicKeyInfo()
    {
        return spkacSeq.getPublicKeyAndChallenge().getSubjectPublicKeyInfo();
    }

    public String getChallenge()
    {
        return spkacSeq.getPublicKeyAndChallenge().getChallengeIA5().getString();
    }

    public byte[] getEncoded()
        throws IOException
    {
        return toASN1Structure().getEncoded();
    }
}
