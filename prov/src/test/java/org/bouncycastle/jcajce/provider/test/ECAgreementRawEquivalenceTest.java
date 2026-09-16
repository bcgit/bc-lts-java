package org.bouncycastle.jcajce.provider.test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;

import javax.crypto.KeyAgreement;

import junit.framework.TestCase;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHCBasicAgreement;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;

/**
 * The EC KeyAgreement SPIs derive their shared secret through a RawAgreement, which writes the
 * field element straight into a byte[], rather than through a BasicAgreement, whose BigInteger
 * result then has to be padded to the curve's field length. The two are meant to produce the same
 * bytes.
 * <p>
 * A round-trip test cannot see a divergence here - both sides of an agreement run the same code, so
 * they would agree with each other whatever that code produced. This compares the JCA result
 * against the BasicAgreement path computed independently, over curves whose field size is and is
 * not a whole number of bytes, and over enough random keys to catch the leading-zero case where a
 * BigInteger is shorter than the field encoding.
 */
public class ECAgreementRawEquivalenceTest
    extends TestCase
{
    private static final String[] CURVES = new String[]
    {
        "P-256",      // 256 bits - whole bytes
        "P-384",
        "P-521",      // 521 bits - 66 byte encoding, not a multiple of 8 bits
        "secp160r1",  // 160 bits, small enough that a short BigInteger shows up often
        "sect283k1"   // binary field
    };

    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testECDHMatchesBasicAgreement()
        throws Exception
    {
        checkAgreement("ECDH", false);
    }

    public void testECDHCMatchesBasicAgreement()
        throws Exception
    {
        checkAgreement("ECDHC", true);
    }

    private void checkAgreement(String algorithm, boolean coFactor)
        throws Exception
    {
        X9IntegerConverter converter = new X9IntegerConverter();

        for (int c = 0; c != CURVES.length; c++)
        {
            KeyPairGenerator kpGen = KeyPairGenerator.getInstance("EC", "BC");

            kpGen.initialize(new ECGenParameterSpec(CURVES[c]), new SecureRandom());

            // several key pairs per curve: a shared secret whose top byte is zero is what
            // separates the two encodings, and that only shows up some of the time
            for (int i = 0; i != 8; i++)
            {
                KeyPair aPair = kpGen.generateKeyPair();
                KeyPair bPair = kpGen.generateKeyPair();

                KeyAgreement agreement = KeyAgreement.getInstance(algorithm, "BC");

                agreement.init(aPair.getPrivate());
                agreement.doPhase(bPair.getPublic(), true);

                byte[] viaProvider = agreement.generateSecret();

                ECPrivateKeyParameters aPriv = (ECPrivateKeyParameters)ECUtil.generatePrivateKeyParameter(aPair.getPrivate());
                ECPublicKeyParameters bPub = (ECPublicKeyParameters)ECUtil.generatePublicKeyParameter(bPair.getPublic());

                byte[] viaBasic;
                if (coFactor)
                {
                    ECDHCBasicAgreement basic = new ECDHCBasicAgreement();
                    basic.init(aPriv);
                    viaBasic = converter.integerToBytes(basic.calculateAgreement(bPub),
                        converter.getByteLength(aPriv.getParameters().getCurve()));
                }
                else
                {
                    ECDHBasicAgreement basic = new ECDHBasicAgreement();
                    basic.init(aPriv);
                    viaBasic = converter.integerToBytes(basic.calculateAgreement(bPub),
                        converter.getByteLength(aPriv.getParameters().getCurve()));
                }

                assertEquals(CURVES[c] + " " + algorithm + ": wrong secret length",
                    viaBasic.length, viaProvider.length);
                assertTrue(CURVES[c] + " " + algorithm + ": raw and basic agreements disagree",
                    Arrays.areEqual(viaBasic, viaProvider));

                // sanity: the secret is not a constant or an all-zero buffer
                assertFalse(CURVES[c] + " " + algorithm + ": secret is all zeroes",
                    Arrays.areEqual(new byte[viaProvider.length], viaProvider));

                // and a different peer key gives a different secret
                KeyAgreement other = KeyAgreement.getInstance(algorithm, "BC");
                other.init(aPair.getPrivate());
                other.doPhase(kpGen.generateKeyPair().getPublic(), true);

                assertFalse(CURVES[c] + " " + algorithm + ": secret independent of the peer key",
                    Arrays.areEqual(viaProvider, other.generateSecret()));
            }
        }
    }
}
