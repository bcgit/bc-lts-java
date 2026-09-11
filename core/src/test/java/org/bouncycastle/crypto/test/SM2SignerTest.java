package org.bouncycastle.crypto.test;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.SM2KeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECConstants;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;
import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestRandomBigInteger;

public class SM2SignerTest
    extends SimpleTest
{
    private static final ECDomainParameters PARAMS_FP_DRAFT = createParamsFpDraft();
    private static final ECDomainParameters PARAMS_F2M = createParamsF2m();

    public String getName()
    {
        return "SM2Signer";
    }

    private void doSignerTestFpDraftSM3()
        throws Exception
    {
        doSignerTest(
            PARAMS_FP_DRAFT,
            new SM3Digest(),
            "ALICE123@YAHOO.COM",
            "message digest",
            "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
            "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",
            "40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1",
            "6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7"
        );
    }

    private void doSignerTestFpDraftSha256()
        throws Exception
    {
        doSignerTest(
            PARAMS_FP_DRAFT,
            new SHA256Digest(),
            "ALICE123@YAHOO.COM",
            "message digest",
            "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263",
            "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F",
            "7D62A5EDBDDC8AF4D69C9E37A60D31F5CEFE8727709117E0869648D0A9AE4F57",
            "1E5E89718B716AAFC6253443168E4F7CF7E1B7B3934307686CE5947C1BD55EDA"
        );
    }

    private void doSignerTestFpStandardSM3()
        throws Exception
    {
        doSignerTest(
            "sm2p256v1",
            new SM3Digest(),
            "sm2test@example.com",
            "hi chappy",
            "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC",
            "3174C6FFC3C279D2422F3FC0A9F3E574674A4490FE45A5325CAF7D3EC4C8F96C",
            "05890B9077B92E47B17A1FF42A814280E556AFD92B4A98B9670BF8B1A274C2FA",
            "E3ABBB8DB2B6ECD9B24ECCEA7F679FB9A4B1DB52F4AA985E443AD73237FA1993"
        );
    }

    private void doSignerTestFpStandardSha256()
        throws Exception
    {
        doSignerTest(
            "sm2p256v1",
            new SHA256Digest(),
            "sm2test@example.com",
            "hi chappy",
            "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC",
            "3174C6FFC3C279D2422F3FC0A9F3E574674A4490FE45A5325CAF7D3EC4C8F96C",
            "94DA20EA69E4FC70692158BF3D30F87682A4B2F84DF4A4829A1EFC5D9C979D3F",
            "EE15AF8D455B728AB80E592FCB654BF5B05620B2F4D25749D263D5C01FAD365F"
        );
    }

    private void doSignerTestFpP256SM3()
        throws Exception
    {
        doSignerTest(
            "P-256",
            new SM3Digest(),
            "sm2_p256_test@example.com",
            "no backdoors here",
            "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC",
            "3174C6FFC3C279D2422F3FC0A9F3E574674A4490FE45A5325CAF7D3EC4C8F96C",
            "96AA39A0C4A5C454653F394E86386F2E38BE14C57D0E555F3A27A5CEF30E51BD",
            "62372BE4AC97DBE725AC0B279BB8FD15883858D814FD792DDB0A401DCC988E70"
        );
    }

    private void doSignerTestFpP256Sha256()
        throws Exception
    {
        doSignerTest(
            "P-256",
            new SHA256Digest(),
            "sm2_p256_test@example.com",
            "no backdoors here",
            "110E7973206F68C19EE5F7328C036F26911C8C73B4E4F36AE3291097F8984FFC",
            "3174C6FFC3C279D2422F3FC0A9F3E574674A4490FE45A5325CAF7D3EC4C8F96C",
            "503D234A22123D7029271EB9E0D763619A69868DE8296C13EDD4CA32D280CFDE",
            "0BDE97699B77268584DDD238DA120095F01130AD2DB37184270F37C02FB2E86B"
        );
    }

    private void doSignerTestF2m()
        throws Exception
    {
        doSignerTest(
            PARAMS_F2M,
            new SM3Digest(),
            "ALICE123@YAHOO.COM",
            "message digest",
            "771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931",
            "36CD79FC8E24B7357A8A7B4A46D454C397703D6498158C605399B341ADA186D6",
            "6D3FBA26EAB2A1054F5D198332E335817C8AC453ED26D3391CD4439D825BF25B",
            "3124C5688D95F0A10252A9BED033BEC84439DA384621B6D6FAD77F94B74A9556"
        );
    }

    private void doSignerTest(String curveName, Digest d, String ident, String msg, String x, String nonce, String r, String s)
        throws Exception
    {
        X9ECParameters x9 = ECNamedCurveTable.getByName(curveName);
        ECDomainParameters domainParams = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());

        doSignerTest(domainParams, d, ident, msg, x, nonce, r, s);
    }

    private void doSignerTest(ECDomainParameters domainParams, Digest d, String ident, String msg, String x, String nonce, String r, String s)
        throws Exception
    {
        implSignerTest(domainParams, d, ident, msg, x, nonce, r, s);
        implSignerTestReuse(domainParams, d, ident, msg, x);
    }

    private void implSignerTest(ECDomainParameters domainParams, Digest d, String ident, String msg, String x, String nonce, String r, String s)
        throws Exception
    {
        byte[] idBytes = Strings.toByteArray(ident);
        byte[] msgBytes = Strings.toByteArray(msg);
        AsymmetricCipherKeyPair kp = generateKeyPair(domainParams, x);

        SM2Signer signer = new SM2Signer(d);

        signer.init(true, new ParametersWithID(
            new ParametersWithRandom(kp.getPrivate(), new TestRandomBigInteger(nonce, 16)),
            idBytes));

        signer.update(msgBytes, 0, msgBytes.length);

        byte[] sig = signer.generateSignature();

        BigInteger[] rs = decode(sig);

        isTrue("r wrong", rs[0].equals(new BigInteger(r, 16)));
        isTrue("s wrong", rs[1].equals(new BigInteger(s, 16)));

        signer.init(false, new ParametersWithID(kp.getPublic(), idBytes));

        signer.update(msgBytes, 0, msgBytes.length);

        isTrue("verification failed", signer.verifySignature(sig));
    }

    private void implSignerTestReuse(ECDomainParameters domainParams, Digest d, String ident, String msg, String x)
        throws Exception
    {
        byte[] idBytes = Strings.toByteArray(ident);
        byte[] msgBytes = Strings.toByteArray(msg);
        AsymmetricCipherKeyPair kp = generateKeyPair(domainParams, x);

        SM2Signer signer = new SM2Signer(d);

        signer.init(true, new ParametersWithID(kp.getPrivate(), idBytes));
        signer.update(msgBytes, 0, msgBytes.length);
        byte[] sig1 = signer.generateSignature();

        signer.update(msgBytes, 0, msgBytes.length);
        byte[] sig2 = signer.generateSignature();

        signer.update((byte)0x00);
        signer.reset();
        signer.update(msgBytes, 0, msgBytes.length);
        byte[] sig3 = signer.generateSignature();

        signer.init(false, new ParametersWithID(kp.getPublic(), idBytes));
        signer.update(msgBytes, 0, msgBytes.length);
        isTrue("verification failed", signer.verifySignature(sig1));

        signer.update(msgBytes, 0, msgBytes.length);
        isTrue("verification failed", signer.verifySignature(sig2));

        signer.update((byte)0x00);
        signer.reset();
        signer.update(msgBytes, 0, msgBytes.length);
        isTrue("verification failed", signer.verifySignature(sig3));
    }

    /**
     * A signer for the case where Z and the message hash are calculated elsewhere and only the
     * resulting e is handed to the signer - see github #2429. The zero-length Z leaves the
     * NullDigest holding exactly the bytes passed to update().
     */
    private static class PrehashSM2Signer
        extends SM2Signer
    {
        PrehashSM2Signer()
        {
            super(new NullDigest());
        }

        protected byte[] getZ(byte[] userID)
        {
            return new byte[0];
        }
    }

    private void doPrehashSignerTest()
        throws Exception
    {
        ECDomainParameters domainParams = PARAMS_FP_DRAFT;

        byte[] idBytes = Strings.toByteArray("ALICE123@YAHOO.COM");
        byte[] msgBytes = Strings.toByteArray("message digest");

        AsymmetricCipherKeyPair kp = generateKeyPair(domainParams, "128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263");

        byte[] e = calculateSM2E(domainParams, (ECPublicKeyParameters)kp.getPublic(), idBytes, msgBytes);

        SM2Signer prehashSigner = new PrehashSM2Signer();

        prehashSigner.init(true, new ParametersWithID(
            new ParametersWithRandom(kp.getPrivate(), new TestRandomBigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16)),
            idBytes));

        prehashSigner.update(e, 0, e.length);

        byte[] sig = prehashSigner.generateSignature();

        BigInteger[] rs = decode(sig);

        // the draft RFC test vector for the message - a pre-hashed sign must land on the same signature
        isTrue("prehash r wrong", rs[0].equals(new BigInteger("40F1EC59F793D9F49E09DCEF49130D4194F79FB1EED2CAA55BACDB49C4E755D1", 16)));
        isTrue("prehash s wrong", rs[1].equals(new BigInteger("6FC6DAC32C5D5CF10C77DFB20F7C2EB667A457872FB09EC56327A67EC7DEEBE7", 16)));

        // a standard signer must accept a signature the pre-hashed one produced
        SM2Signer signer = new SM2Signer();

        signer.init(false, new ParametersWithID(kp.getPublic(), idBytes));
        signer.update(msgBytes, 0, msgBytes.length);
        isTrue("standard verify of prehash signature failed", signer.verifySignature(sig));

        // ... and the pre-hashed one a signature the standard signer produced
        signer.init(true, new ParametersWithID(
            new ParametersWithRandom(kp.getPrivate(), new TestRandomBigInteger("6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F", 16)),
            idBytes));
        signer.update(msgBytes, 0, msgBytes.length);
        byte[] stdSig = signer.generateSignature();

        isTrue("prehash signature not the same as the standard one", areEqual(sig, stdSig));

        prehashSigner.init(false, new ParametersWithID(kp.getPublic(), idBytes));
        prehashSigner.update(e, 0, e.length);
        isTrue("prehash verify of standard signature failed", prehashSigner.verifySignature(stdSig));

        // a wrong e must not verify
        byte[] wrongE = Arrays.clone(e);

        wrongE[0] ^= 0x01;

        prehashSigner.init(false, new ParametersWithID(kp.getPublic(), idBytes));
        prehashSigner.update(wrongE, 0, wrongE.length);
        isTrue("prehash verify of altered e succeeded", !prehashSigner.verifySignature(stdSig));

        // reuse: the signer must go back to a clean e on reset()
        prehashSigner.init(false, new ParametersWithID(kp.getPublic(), idBytes));
        prehashSigner.update(wrongE, 0, wrongE.length);
        prehashSigner.reset();
        prehashSigner.update(e, 0, e.length);
        isTrue("prehash verify after reset failed", prehashSigner.verifySignature(stdSig));
    }

    private static byte[] calculateSM2E(ECDomainParameters domainParams, ECPublicKeyParameters pubKey, byte[] idBytes, byte[] msgBytes)
    {
        Digest digest = new SM3Digest();

        int len = idBytes.length * 8;

        digest.update((byte)(len >>> 8));
        digest.update((byte)len);
        digest.update(idBytes, 0, idBytes.length);

        addFieldElement(digest, domainParams.getCurve().getA());
        addFieldElement(digest, domainParams.getCurve().getB());
        addFieldElement(digest, domainParams.getG().getAffineXCoord());
        addFieldElement(digest, domainParams.getG().getAffineYCoord());

        ECPoint q = pubKey.getQ().normalize();

        addFieldElement(digest, q.getAffineXCoord());
        addFieldElement(digest, q.getAffineYCoord());

        byte[] z = new byte[digest.getDigestSize()];

        digest.doFinal(z, 0);

        digest.update(z, 0, z.length);
        digest.update(msgBytes, 0, msgBytes.length);

        byte[] e = new byte[digest.getDigestSize()];

        digest.doFinal(e, 0);

        return e;
    }

    private static void addFieldElement(Digest digest, ECFieldElement v)
    {
        byte[] p = v.getEncoded();

        digest.update(p, 0, p.length);
    }

    private void doVerifyBoundsCheck()
        throws IOException
    {
        ECDomainParameters domainParams = PARAMS_F2M;

        AsymmetricCipherKeyPair kp = generateKeyPair(domainParams, "771EF3DBFF5F1CDC32B9C572930476191998B2BF7CB981D7F5B39202645F0931");

        SM2Signer signer = new SM2Signer();

        signer.init(false, kp.getPublic());

        signer.update(new byte[20], 0, 20);
        isTrue(!signer.verifySignature(encode(ECConstants.ZERO, ECConstants.EIGHT)));

        signer.update(new byte[20], 0, 20);
        isTrue(!signer.verifySignature(encode(ECConstants.EIGHT, ECConstants.ZERO)));

        signer.update(new byte[20], 0, 20);
        isTrue(!signer.verifySignature(encode(domainParams.getN(), ECConstants.EIGHT)));

        signer.update(new byte[20], 0, 20);
        isTrue(!signer.verifySignature(encode(ECConstants.EIGHT, domainParams.getN())));
    }

    private void doKeyGenAndSignBoundsCheck()
        throws Exception
    {
        SM2KeyPairGenerator sm2KpGen = new SM2KeyPairGenerator();

        ECDomainParameters paramsFpDraft = createParamsFpDraft();

        // we expect it to reject N-1
        try
        {
            sm2KpGen.init(new ECKeyGenerationParameters(paramsFpDraft, new FixedSecureRandom(BigIntegers.asUnsignedByteArray(paramsFpDraft.getN().subtract(BigIntegers.ONE)))));

            sm2KpGen.generateKeyPair();

            fail("no exception");
        }
        catch (ArrayIndexOutOfBoundsException e)
        {
            // continue
        }

        ECKeyPairGenerator ecKpGen = new ECKeyPairGenerator();

        ecKpGen.init(new ECKeyGenerationParameters(paramsFpDraft, new FixedSecureRandom(BigIntegers.asUnsignedByteArray(paramsFpDraft.getN().subtract(BigIntegers.ONE)))));

        AsymmetricCipherKeyPair kp = ecKpGen.generateKeyPair();

        SM2Signer signer = new SM2Signer();

        try
        {
            signer.init(true, kp.getPrivate());
            fail("no exception");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("SM2 private key out of range", e.getMessage());
        }
    }

    public void performTest()
        throws Exception
    {
        doSignerTestFpDraftSM3();
        doSignerTestFpDraftSha256();
        doSignerTestFpStandardSM3();
        doSignerTestFpStandardSha256();
        doSignerTestFpP256SM3();
        doSignerTestFpP256Sha256();
        doSignerTestF2m();
        doPrehashSignerTest();
        doVerifyBoundsCheck();
        doKeyGenAndSignBoundsCheck();
    }

    private static ECDomainParameters createParamsFpDraft()
    {
        BigInteger SM2_ECC_P = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3", 16);
        BigInteger SM2_ECC_A = new BigInteger("787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498", 16);
        BigInteger SM2_ECC_B = new BigInteger("63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A", 16);
        BigInteger SM2_ECC_N = new BigInteger("8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7", 16);
        BigInteger SM2_ECC_H = ECConstants.ONE;
        BigInteger SM2_ECC_GX = new BigInteger("421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D", 16);
        BigInteger SM2_ECC_GY = new BigInteger("0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2", 16);

        ECCurve curve = new ECCurve.Fp(SM2_ECC_P, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        return new ECDomainParameters(curve, g, SM2_ECC_N, SM2_ECC_H);
    }

    private static ECDomainParameters createParamsF2m()
    {
        BigInteger SM2_ECC_A = new BigInteger("00", 16);
        BigInteger SM2_ECC_B = new BigInteger("E78BCD09746C202378A7E72B12BCE00266B9627ECB0B5A25367AD1AD4CC6242B", 16);
        BigInteger SM2_ECC_N = new BigInteger("7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBC972CF7E6B6F900945B3C6A0CF6161D", 16);
        BigInteger SM2_ECC_H = BigInteger.valueOf(4);
        BigInteger SM2_ECC_GX = new BigInteger("00CDB9CA7F1E6B0441F658343F4B10297C0EF9B6491082400A62E7A7485735FADD", 16);
        BigInteger SM2_ECC_GY = new BigInteger("013DE74DA65951C4D76DC89220D5F7777A611B1C38BAE260B175951DC8060C2B3E", 16);

        ECCurve curve = new ECCurve.F2m(257, 12, SM2_ECC_A, SM2_ECC_B, SM2_ECC_N, SM2_ECC_H);
        ECPoint g = curve.createPoint(SM2_ECC_GX, SM2_ECC_GY);
        return new ECDomainParameters(curve, g, SM2_ECC_N, SM2_ECC_H);
    }

    private static BigInteger[] decode(byte[] sig)
    {
        ASN1Sequence s = ASN1Sequence.getInstance(sig);

        return new BigInteger[] {
            decodeValue(s.getObjectAt(0)),
            decodeValue(s.getObjectAt(1)) };
    }

    private static BigInteger decodeValue(ASN1Encodable e)
    {
        return ASN1Integer.getInstance(e).getValue();
    }

    private static byte[] encode(BigInteger r, BigInteger s)
        throws IOException
    {
        return new DERSequence(new ASN1Encodable[] { new ASN1Integer(r), new ASN1Integer(s)}).getEncoded();
    }

    private static AsymmetricCipherKeyPair generateKeyPair(ECDomainParameters domainParams, String x)
    {
        ECKeyPairGenerator kpg = new ECKeyPairGenerator();
        kpg.init(new ECKeyGenerationParameters(domainParams, new TestRandomBigInteger(x, 16)));
        return kpg.generateKeyPair();
    }

    public static void main(String[] args)
    {
        runTest(new SM2SignerTest());
    }
}
