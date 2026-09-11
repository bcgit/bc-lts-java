package org.bouncycastle.crypto.test;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.cryptopro.ECGOST3410NamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.digests.GOST3411Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.ECGOST3410Signer;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomData;

/**
 *  ECGOST3410 tests are taken from GOST R 34.10-2001.
 */
public class ECGOST3410Test
    extends SimpleTest
 {
    byte[] hashmessage = Hex.decode("3042453136414534424341374533364339313734453431443642453241453435");
    
     /**
     * ECGOST3410 over the field Fp<br>
     */
    BigInteger r = new BigInteger("29700980915817952874371204983938256990422752107994319651632687982059210933395");
    BigInteger s = new BigInteger("574973400270084654178925310019147038455227042649098563933718999175515839552");

    byte[] kData = new BigInteger("53854137677348463731403841147996619241504003434302020712960838528893196233395").toByteArray();

    SecureRandom    k = new TestRandomData(kData);

    private void ecGOST3410_TEST()
    {
        BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p
        BigInteger mod_q = new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619");

        ECCurve.Fp curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("7"), // a
            new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414"), // b
            mod_q, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("2"), // x
                new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280")), // y
            mod_q);

        ECPrivateKeyParameters priKey = new ECPrivateKeyParameters(
            new BigInteger("55441196065363246126355624130324183196576709222340016572108097750006097525544"), // d
            params);

        ParametersWithRandom param = new ParametersWithRandom(priKey, k);

        ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

        ecgost3410.init(true, param);

        byte[] mVal = new BigInteger("20798893674476452017134061561508270130637142515379653289952617252661468872421").toByteArray();
        byte[] message = new byte[mVal.length];
        
        for (int i = 0; i != mVal.length; i++)
        {
            message[i] = mVal[mVal.length - 1 - i];
        }
        
        BigInteger[] sig = ecgost3410.generateSignature(message);

        if (!r.equals(sig[0]))
        {
            fail("r component wrong.", r, sig[0]);
        }

        if (!s.equals(sig[1]))
        {
            fail("s component wrong.", s, sig[1]);
        }

        // Verify the signature
        ECPublicKeyParameters pubKey = new ECPublicKeyParameters(
            curve.createPoint(
                new BigInteger("57520216126176808443631405023338071176630104906313632182896741342206604859403"), // x
                new BigInteger("17614944419213781543809391949654080031942662045363639260709847859438286763994")), // y
            params);

        ecgost3410.init(false, pubKey);
        if (!ecgost3410.verifySignature(message, sig[0], sig[1]))
        {
            fail("verification fails");
        }
    }

    /**
     * Test Sign & Verify with test parameters
     * see: https://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-TestParamSet  P.46
     */
    private void ecGOST3410_TestParam()
    {
        SecureRandom    random = new SecureRandom();

        BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564821041"); //p
        BigInteger mod_q = new BigInteger("57896044618658097711785492504343953927082934583725450622380973592137631069619");

        ECCurve.Fp curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("7"), // a
            new BigInteger("43308876546767276905765904595650931995942111794451039583252968842033849580414"), // b
            mod_q, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("2"), // x
                new BigInteger("4018974056539037503335449422937059775635739389905545080690979365213431566280")), // y
            mod_q);

        ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                        params,
                                        random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

        ecgost3410.init(true, param);

        //get hash message using the digest GOST3411.
        byte[] message = "Message for sign".getBytes();
        GOST3411Digest  gost3411 = new GOST3411Digest();
        gost3411.update(message, 0, message.length);
        byte[] hashmessage = new byte[gost3411.getDigestSize()];
        gost3411.doFinal(hashmessage, 0);

        BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

        ecgost3410.init(false, pair.getPublic());

        if (!ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * Test Sign & Verify with A parameters
     * see: https://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-CryptoPro-A-ParamSet  P.47
     */
    public void ecGOST3410_AParam()
    {
        SecureRandom random = new SecureRandom();

        BigInteger mod_p = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639319"); //p
        BigInteger mod_q = new BigInteger("115792089237316195423570985008687907853073762908499243225378155805079068850323");

        ECCurve.Fp curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639316"), // a
            new BigInteger("166"), // b
            mod_q, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("1"), // x
                new BigInteger("64033881142927202683649881450433473985931760268884941288852745803908878638612")), // y
            mod_q);

        ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                        params,
                                        random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

        ecgost3410.init(true, param);

        BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

        ecgost3410.init(false, pair.getPublic());

        if (!ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * Test Sign & Verify with B parameters
     * see: https://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-CryptoPro-B-ParamSet  P.47-48
     */
    private void ecGOST3410_BParam()
    {
        SecureRandom    random = new SecureRandom();

        BigInteger mod_p = new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823193"); //p
        BigInteger mod_q = new BigInteger("57896044618658097711785492504343953927102133160255826820068844496087732066703");

        ECCurve.Fp curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564823190"), // a
            new BigInteger("28091019353058090096996979000309560759124368558014865957655842872397301267595"), // b
            mod_q, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("1"), // x
                new BigInteger("28792665814854611296992347458380284135028636778229113005756334730996303888124")), // y
            mod_q);

        ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                        params,
                                        random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

        ecgost3410.init(true, param);

        BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

        ecgost3410.init(false, pair.getPublic());

        if (!ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * Test Sign & Verify with C parameters
     * see: https://www.ietf.org/internet-drafts/draft-popov-cryptopro-cpalgs-01.txt
     * gostR3410-2001-CryptoPro-C-ParamSet  P.48
     */
    private void ecGOST3410_CParam()
    {
        SecureRandom    random = new SecureRandom();

        BigInteger mod_p = new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502619"); //p
        BigInteger mod_q = new BigInteger("70390085352083305199547718019018437840920882647164081035322601458352298396601");

        ECCurve.Fp curve = new ECCurve.Fp(
            mod_p, // p
            new BigInteger("70390085352083305199547718019018437841079516630045180471284346843705633502616"), // a
            new BigInteger("32858"), // b
            mod_q, ECConstants.ONE);

        ECDomainParameters params = new ECDomainParameters(
            curve,
            curve.createPoint(
                new BigInteger("0"), // x
                new BigInteger("29818893917731240733471273240314769927240550812383695689146495261604565990247")), // y
            mod_q);

        ECKeyPairGenerator          pGen = new ECKeyPairGenerator();
        ECKeyGenerationParameters   genParam = new ECKeyGenerationParameters(
                                        params,
                                        random);

        pGen.init(genParam);

        AsymmetricCipherKeyPair  pair = pGen.generateKeyPair();

        ParametersWithRandom param = new ParametersWithRandom(pair.getPrivate(), random);

        ECGOST3410Signer ecgost3410 = new ECGOST3410Signer();

        ecgost3410.init(true, param);

        BigInteger[] sig = ecgost3410.generateSignature(hashmessage);

        ecgost3410.init(false, pair.getPublic());

        if (!ecgost3410.verifySignature(hashmessage, sig[0], sig[1]))
        {
            fail("signature fails");
        }
    }

    /**
     * The nonce is drawn over n.bitLength() bits, so on a curve whose order sits well below that
     * power of two a draw can land at or past n. Such a draw has to be discarded and replaced
     * rather than folded down by the reduction that follows: folding makes the bottom of the range
     * likelier than the top, which is the bias a lattice attack consumes. GostR3410-2001-CryptoPro-C
     * is one of the curves where it can happen - its order is about 0.61 of 2^256.
     * <p>
     * So an out-of-range draw followed by an in-range one must produce exactly the signature the
     * in-range value produces on its own.
     */
    private void ecGOST3410_NonceRange()
    {
        X9ECParameters x9 = ECGOST3410NamedCurves.getByNameX9("GostR3410-2001-CryptoPro-C");
        ECDomainParameters params = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN());
        BigInteger n = params.getN();

        // the curve has to be one where the draw can exceed the order, or the test proves nothing
        if (n.bitLength() != 256 || n.compareTo(ECConstants.ONE.shiftLeft(255)) <= 0)
        {
            fail("CryptoPro-C order is not the shape this test needs");
        }

        BigInteger inRange = n.subtract(BigInteger.valueOf(12345));
        BigInteger outOfRange = n.add(BigInteger.valueOf(12345));

        if (outOfRange.bitLength() > 256)
        {
            fail("the out of range value does not fit the width of the draw");
        }

        ECPrivateKeyParameters priv = new ECPrivateKeyParameters(
            new BigInteger("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20", 16), params);

        byte[] message = new byte[32];
        for (int i = 0; i != message.length; i++)
        {
            message[i] = (byte)i;
        }

        BigInteger[] afterReject;
        try
        {
            afterReject = signWith(priv, message,
                new FixedSecureRandom(new FixedSecureRandom.Source[]
                {
                    new FixedSecureRandom.BigInteger(nonceBytes(outOfRange)),
                    new FixedSecureRandom.BigInteger(nonceBytes(inRange))
                }));
        }
        catch (IllegalArgumentException e)
        {
            // the constant-time assembly needs its operands reduced, so a draw that is not
            // redrawn now fails here rather than being folded silently as it once was
            fail("nonce at or past the order was not redrawn: " + e.getMessage());
            return;
        }

        BigInteger[] direct = signWith(priv, message,
            new FixedSecureRandom(new FixedSecureRandom.Source[]
            {
                new FixedSecureRandom.BigInteger(nonceBytes(inRange))
            }));

        if (!afterReject[0].equals(direct[0]) || !afterReject[1].equals(direct[1]))
        {
            fail("nonce at or past the order was folded rather than redrawn");
        }

        ECGOST3410Signer verifier = new ECGOST3410Signer();
        verifier.init(false, new ECPublicKeyParameters(
            params.getG().multiply(priv.getD()).normalize(), params));

        if (!verifier.verifySignature(message, afterReject[0], afterReject[1]))
        {
            fail("signature after a rejected nonce does not verify");
        }
    }

    private BigInteger[] signWith(ECPrivateKeyParameters priv, byte[] message, SecureRandom random)
    {
        ECGOST3410Signer signer = new ECGOST3410Signer();

        signer.init(true, new ParametersWithRandom(priv, random));

        return signer.generateSignature(message);
    }

    private static byte[] nonceBytes(BigInteger k)
    {
        return BigIntegers.asUnsignedByteArray(32, k);
    }

    public String getName()
    {
        return "ECGOST3410";
    }

    public void performTest()
    {
        ecGOST3410_TEST();
        ecGOST3410_TestParam();
        ecGOST3410_AParam();
        ecGOST3410_BParam();
        ecGOST3410_CParam();
        ecGOST3410_NonceRange();
    }

    public static void main(
        String[]    args)
    {
        runTest(new ECGOST3410Test());
    }
}
