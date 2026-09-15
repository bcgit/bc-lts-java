package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V2TBSCertListGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.test.SimpleTest;

public class CRL5Test
    extends SimpleTest
{
    byte[] inDirectCrl = Base64.decode(
            "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");
    
    byte[] directCRL = Base64.decode(
            "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"
            +"MQ==");
        
 
    public String getName()
    {
        return "CRL5";
    }
   
    public void indirectCRLTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        ByteArrayInputStream in = new ByteArrayInputStream(inDirectCrl);
        X509CRL crl = (X509CRL) cf.generateCRL(in);
        Set set = crl.getRevokedCertificates();
        Iterator it = set.iterator();
        while (it.hasNext())
        {
            if (((X509CRLEntry)it.next()).getCertificateIssuer() == null)
            {
                fail("certificate issuer CRL entry extension is null");
            }
        }
    } 

    public void directCRLTest()
        throws Exception
    {
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        ByteArrayInputStream in = new ByteArrayInputStream(directCRL);
        X509CRL crl = (X509CRL) cf.generateCRL(in);
        Set set = crl.getRevokedCertificates();
        Iterator it = set.iterator();
        while (it.hasNext())
        {
            if (((X509CRLEntry)it.next()).getCertificateIssuer() != null)
            {
                fail("certificate issuer CRL entry extension is not null");
            }
        }
    }
    
    /**
     * An entry's certificateIssuer that does not decode to a directoryName must not escape the
     * java.security.cert.X509CRL accessors as an unchecked exception, and one that carries a
     * directoryName after some other GeneralName must still be found - github #2425.
     */
    public void malformedCertificateIssuerTest()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(2048);

        KeyPair kp = kpg.generateKeyPair();
        X500Name crlIssuer = new X500Name("CN=Indirect CRL Issuer");
        X509Certificate cert = TestCertificateGen.createSelfSignedCert(
            crlIssuer, "SHA256withRSA", kp);
        BigInteger serial = cert.getSerialNumber();
        X500Name otherIssuer = new X500Name("CN=Other Issuer");

        // a directoryName, first or after another GeneralName, names the entry's issuer either way
        checkIndirectCRL("directoryName", new GeneralNames(new GeneralName(otherIssuer)),
            crlIssuer, cert, serial, otherIssuer, false);
        checkIndirectCRL("dNSName then directoryName", new GeneralNames(new GeneralName[]
            {
                new GeneralName(GeneralName.dNSName, "example.com"),
                new GeneralName(otherIssuer)
            }), crlIssuer, cert, serial, otherIssuer, false);

        // no directoryName to be had: the entry has no certificate issuer of its own, so it is the CRL issuer's
        checkIndirectCRL("empty GeneralNames", new DERSequence(),
            crlIssuer, cert, serial, null, true);
        checkIndirectCRL("dNSName only", new GeneralNames(new GeneralName(GeneralName.dNSName, "example.com")),
            crlIssuer, cert, serial, null, true);
    }

    private void checkIndirectCRL(String label, ASN1Encodable certificateIssuer, X500Name crlIssuer,
                                  X509Certificate cert, BigInteger serial,
                                  X500Name expectedEntryIssuer, boolean expectedRevoked)
        throws Exception
    {
        byte[] enc = createIndirectCRL(crlIssuer, certificateIssuer, serial);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
        X509CRL crl = (X509CRL)cf.generateCRL(new ByteArrayInputStream(enc));

        Set set = crl.getRevokedCertificates();
        if (set == null || set.size() != 2)
        {
            fail(label + ": expected 2 revoked certificates");
        }

        X509CRLEntry entry = crl.getRevokedCertificate(serial);
        if (entry == null)
        {
            fail(label + ": entry for the queried serial not found");
        }

        if (expectedEntryIssuer == null)
        {
            if (entry.getCertificateIssuer() != null)
            {
                fail(label + ": expected no certificate issuer on the entry");
            }
        }
        else if (!new X500Name(entry.getCertificateIssuer().getName()).equals(expectedEntryIssuer))
        {
            fail(label + ": wrong certificate issuer on the entry");
        }

        isTrue(label + ": wrong revocation status", expectedRevoked == crl.isRevoked(cert));
    }

    private byte[] createIndirectCRL(X500Name crlIssuer, ASN1Encodable certificateIssuer, BigInteger serial)
        throws Exception
    {
        AlgorithmIdentifier sigAlg = new AlgorithmIdentifier(
            PKCSObjectIdentifiers.sha256WithRSAEncryption, DERNull.INSTANCE);
        Date now = new Date();

        V2TBSCertListGenerator gen = new V2TBSCertListGenerator();

        gen.setIssuer(crlIssuer);
        gen.setSignature(sigAlg);
        gen.setThisUpdate(new Time(now));
        gen.setNextUpdate(new Time(new Date(now.getTime() + 86400000L)));

        ExtensionsGenerator crlExts = new ExtensionsGenerator();
        crlExts.addExtension(Extension.issuingDistributionPoint, true,
            new IssuingDistributionPoint(null, false, false, null, true, false));
        gen.setExtensions(crlExts.generate());

        // the entry carrying the certificateIssuer under test - the issuer it names carries
        // forward to the entry that follows, which is the one the accessors are asked about
        ExtensionsGenerator entryExts = new ExtensionsGenerator();
        entryExts.addExtension(Extension.certificateIssuer, true, certificateIssuer);
        gen.addCRLEntry(new ASN1Integer(BigInteger.ONE), new Time(now), entryExts.generate());
        gen.addCRLEntry(new ASN1Integer(serial), new Time(now), 0);

        // these accessors do not verify the signature, so its value is immaterial here
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(gen.generateTBSCertList());
        v.add(sigAlg);
        v.add(new DERBitString(new byte[256]));

        return new DERSequence(v).getEncoded(ASN1Encoding.DER);
    }

    public void performTest()
        throws Exception
    {
        indirectCRLTest();
        directCRLTest();
        malformedCertificateIssuerTest();
    }

    public static void main(
        String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new CRL5Test());
    }
}
