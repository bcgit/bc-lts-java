package org.bouncycastle.pqc.crypto.test;

import java.security.SecureRandom;

import junit.framework.TestCase;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/**
 * An ML-DSA or ML-KEM private key in the pre-RFC raw form is its expanded key as the content of the
 * privateKey OCTET STRING. That content is random, so it can begin with bytes that read as a DER tag and
 * a length covering the rest; both key factories now take content of the expanded key's length as the
 * raw key before trying to parse it. The prefix is forced onto real keys here where nothing binds those
 * bytes: the ML-KEM keys and the legacy ML-DSA key class. The current ML-DSA key class checks tr, which binds
 * rho, so a forced prefix is refused there and a key whose rho begins with such a prefix (found by search,
 * as upstream does) is used instead. An ML-DSA encoding of neither the seed's nor the expanded key's length,
 * which the legacy key class used to slice and pad into a different key, is refused.
 */
public class MLRawPrivateKeyFormTest
    extends TestCase
{
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int[] PREFIXES = { 0x04, 0x30, 0x80 };

    public void testLegacyStack()
        throws Exception
    {
        org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator dsa = new org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator();
        dsa.init(new org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters(RANDOM,
            org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters.ml_dsa_44));
        byte[] dsaKey = ((org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters)dsa.generateKeyPair().getPrivate()).getPrivateKey();

        org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator kem = new org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator();
        kem.init(new org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters(RANDOM,
            org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters.ml_kem_512));
        byte[] kemKey = ((org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters)kem.generateKeyPair().getPrivate()).getEncoded();

        for (int i = 0; i != PREFIXES.length; i++)
        {
            byte[] d = misleading(dsaKey, PREFIXES[i]);
            assertTrue(Arrays.areEqual(d, ((org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters)
                org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(raw(NISTObjectIdentifiers.id_ml_dsa_44, d))).getPrivateKey()));
            byte[] k = misleading(kemKey, PREFIXES[i]);
            assertTrue(Arrays.areEqual(k, ((org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters)
                org.bouncycastle.pqc.crypto.util.PrivateKeyFactory.createKey(raw(NISTObjectIdentifiers.id_alg_ml_kem_512, k))).getEncoded()));
        }

        try
        {
            new org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters(
                org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters.ml_dsa_44, Arrays.copyOf(dsaKey, dsaKey.length - 4), null);
            fail("short ML-DSA encoding accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("'encoding' has invalid length", e.getMessage());
        }
    }

    public void testStack()
        throws Exception
    {
        // this seed's rho begins 77 82 09 fc: a tag and the length 2556 covering the rest of an ML-DSA-44 expanded key
        byte[] dsaKey = new org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters(
            org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_44,
            Hex.decode("9dd9520100000000000000000000000000000000000000000000000000000000")).getEncoded();
        assertTrue(Arrays.areEqual(Hex.decode("778209fc"), Arrays.copyOf(dsaKey, 4)));
        assertTrue(Arrays.areEqual(dsaKey, ((org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters)
            org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(raw(NISTObjectIdentifiers.id_ml_dsa_44, dsaKey))).getPrivateKey()));

        org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator kem = new org.bouncycastle.crypto.generators.MLKEMKeyPairGenerator();
        kem.init(new org.bouncycastle.crypto.params.MLKEMKeyGenerationParameters(RANDOM,
            org.bouncycastle.crypto.params.MLKEMParameters.ml_kem_512));
        byte[] kemKey = ((org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters)kem.generateKeyPair().getPrivate()).getEncoded();

        for (int i = 0; i != PREFIXES.length; i++)
        {
            // a prefix forced onto an ML-DSA key changes rho, so the key no longer matches its tr
            byte[] d = misleading(dsaKey, PREFIXES[i]);
            try
            {
                org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(raw(NISTObjectIdentifiers.id_ml_dsa_44, d));
                fail("ML-DSA key with a forced prefix accepted");
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("'encoding' has inconsistent tr", e.getMessage());
            }
            byte[] k = misleading(kemKey, PREFIXES[i]);
            assertTrue(Arrays.areEqual(k, ((org.bouncycastle.crypto.params.MLKEMPrivateKeyParameters)
                org.bouncycastle.crypto.util.PrivateKeyFactory.createKey(raw(NISTObjectIdentifiers.id_alg_ml_kem_512, k))).getEncoded()));
        }
    }

    // the key's first bytes replaced by a tag and a two-byte length covering exactly the rest
    private static byte[] misleading(byte[] key, int tag)
    {
        byte[] m = Arrays.clone(key);
        m[0] = (byte)tag;
        m[1] = (byte)0x82;
        m[2] = (byte)((key.length - 4) >> 8);
        m[3] = (byte)(key.length - 4);
        return m;
    }

    // a PrivateKeyInfo whose privateKey OCTET STRING holds the given bytes as its content
    private static PrivateKeyInfo raw(ASN1ObjectIdentifier oid, byte[] content)
    {
        return PrivateKeyInfo.getInstance(new DERSequence(new ASN1Encodable[]{ new ASN1Integer(0),
            new AlgorithmIdentifier(oid), new DEROctetString(content) }));
    }
}
