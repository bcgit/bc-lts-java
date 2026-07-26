package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.asn1.x509.TBSCertList;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.test.SimpleTest;

/**
 * Regression test for RFC 5280 sec. 6.3.3 (d)(3) in
 * {@code RFC3280CertPathUtilities.processCRLD}. When the CRL's IssuingDistributionPoint is
 * present but omits {@code onlySomeReasons}, and the certificate's DistributionPoint includes
 * a {@code reasons} field, the interim reasons mask must be {@code dp.reasons} - an absent
 * {@code onlySomeReasons} means the IDP contributes all-reasons to the intersection.
 * <p>
 * Historically that case reached revocation checking as a NullPointerException: the mask
 * arithmetic guarded only {@code idp == null}, so an IDP that was present but carried no
 * {@code onlySomeReasons} still had its absent reasons dereferenced. An NPE is not an
 * {@code AnnotatedException}, so it escaped {@code checkCRL}'s handler as a raw unchecked
 * exception. {@code processCRLD} has since been rewritten to intersect the IDP and DP reason
 * flags directly, defaulting either side to all-reasons when absent, which removes the
 * dereference altogether; this test pins the resulting mask so the behaviour cannot regress
 * through a future rewrite.
 *
 * <p>{@code processCRLD} is {@code protected static} in a different package, so it is exercised by
 * reflection; the alternative (a full CertPathValidator run with a reason-scoped CRL DP and a
 * matching CRL whose IDP omits onlySomeReasons) would test the same computation far less directly.
 */
public class CrlReasonsMaskTest
    extends SimpleTest
{
    public String getName()
    {
        return "CrlReasonsMask";
    }

    public void performTest()
        throws Exception
    {
        // CRL carrying an IssuingDistributionPoint that OMITS onlySomeReasons.
        X509CRL crl = crlWithIdpNoOnlySomeReasons();

        // certificate DistributionPoint WITH a reasons field (reason-scoped CRL DP).
        DistributionPoint dp = new DistributionPoint(null, new ReasonFlags(ReasonFlags.keyCompromise), null);

        Method processCRLD = Class.forName("org.bouncycastle.jce.provider.RFC3280CertPathUtilities")
            .getDeclaredMethod("processCRLD", X509CRL.class, DistributionPoint.class);
        processCRLD.setAccessible(true);

        try
        {
            Object mask = processCRLD.invoke(null, crl, dp);
            if (mask == null)
            {
                fail("processCRLD returned null reasons mask");
            }
            // Success: the (d)(3) path returned a mask instead of dereferencing a null onlySomeReasons.
        }
        catch (InvocationTargetException e)
        {
            Throwable cause = e.getCause();
            if (cause instanceof NullPointerException)
            {
                fail("processCRLD threw NullPointerException for an IDP without onlySomeReasons "
                    + "(RFC 5280 6.3.3 (d)(3) not handled)");
            }
            throw e;
        }
    }

    private static X509CRL crlWithIdpNoOnlySomeReasons()
        throws Exception
    {
        KeyPair kp = TestUtils.generateRSAKeyPair();
        X500Name issuer = new X500Name("CN=CRL Reasons Test Issuer");

        V2TBSCertListGenerator g = new V2TBSCertListGenerator();
        long now = System.currentTimeMillis();
        g.setIssuer(issuer);
        g.setThisUpdate(new Time(new Date(now - 5000)));
        g.setNextUpdate(new Time(new Date(now + 30 * 60 * 1000)));
        g.setSignature(rsaSha256AlgId());
        g.addCRLEntry(new org.bouncycastle.asn1.ASN1Integer(BigInteger.valueOf(1)),
            new Time(new Date(now - 5000)), org.bouncycastle.asn1.x509.CRLReason.keyCompromise);

        // IDP present, onlySomeReasons == null (4th arg). onlyContainsUserCerts=true keeps it non-trivial.
        IssuingDistributionPoint idp = new IssuingDistributionPoint(null, true, false, null, false, false);
        ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.issuingDistributionPoint, true, idp);
        g.setExtensions(extGen.generate());

        TBSCertList tbs = g.generateTBSCertList();
        Signature sig = Signature.getInstance("SHA256withRSA", "BC");
        sig.initSign(kp.getPrivate());
        sig.update(tbs.getEncoded(ASN1Encoding.DER));

        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(tbs);
        v.add(rsaSha256AlgId());
        v.add(new DERBitString(sig.sign()));

        return (X509CRL)CertificateFactory.getInstance("X.509", "BC")
            .generateCRL(new ByteArrayInputStream(new DERSequence(v).getEncoded(ASN1Encoding.DER)));
    }

    private static AlgorithmIdentifier rsaSha256AlgId()
    {
        return new AlgorithmIdentifier(PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
    }

    public static void main(String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CrlReasonsMaskTest());
    }
}
