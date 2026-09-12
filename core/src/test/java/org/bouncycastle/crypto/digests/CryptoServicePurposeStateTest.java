package org.bouncycastle.crypto.digests;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.Test;
import org.bouncycastle.util.test.TestResult;

/**
 * Confirms that a digest's encoded state carries {@link CryptoServicePurpose} via its stable
 * {@link CryptoServicePurpose#getCode()} rather than {@link Enum#ordinal()}. The two coincide
 * today (the codes were assigned to match declaration order), so a positive-only round trip
 * would not by itself distinguish the fixed-code scheme from an ordinal-based one that a future
 * edit could silently re-introduce (e.g. by reordering the enum, or restoring state produced by
 * a build with a different declaration order) - that reintroduction would not throw, it would
 * silently hand back the *wrong* purpose (a type-confusion on restore). This test therefore
 * pins the wire byte to the documented code for every purpose value, not just to whatever the
 * current ordinal happens to be, and separately confirms malformed purpose bytes are rejected
 * rather than silently mapped to some other purpose.
 */
public class CryptoServicePurposeStateTest
    extends SimpleTest
{
    public String getName()
    {
        return "CryptoServicePurposeState";
    }

    public void performTest()
        throws Exception
    {
        testCodeContract();
        testInvalidCodeRejected();

        SecureRandom random = new SecureRandom();

        for (CryptoServicePurpose purpose : CryptoServicePurpose.values())
        {
            checkGeneralDigest(new SHA1Digest(purpose), purpose, random);
            checkGeneralDigest(new MD5Digest(purpose), purpose, random);
            checkGeneralDigest(new SHA224Digest(purpose), purpose, random);
            checkGeneralDigest(new SHA256Digest(purpose), purpose, random);

            checkLongDigest(new SHA384Digest(purpose), purpose, random);
            checkLongDigest(new SHA512Digest(purpose), purpose, random);
            checkLongDigest(new SHA512tDigest(224, purpose), purpose, random);

            checkKeccak(new SHA3Digest(256, purpose), purpose, random);
        }
    }

    private void testCodeContract()
    {
        // The codes are part of the wire format (the trailing byte of a digest's encoded
        // state) and so must be exactly these values regardless of enum declaration order.
        isEquals(0, CryptoServicePurpose.AGREEMENT.getCode());
        isEquals(1, CryptoServicePurpose.ENCRYPTION.getCode());
        isEquals(2, CryptoServicePurpose.DECRYPTION.getCode());
        isEquals(3, CryptoServicePurpose.KEYGEN.getCode());
        isEquals(4, CryptoServicePurpose.SIGNING.getCode());
        isEquals(5, CryptoServicePurpose.VERIFYING.getCode());
        isEquals(6, CryptoServicePurpose.AUTHENTICATION.getCode());
        isEquals(7, CryptoServicePurpose.VERIFICATION.getCode());
        isEquals(8, CryptoServicePurpose.PRF.getCode());
        isEquals(9, CryptoServicePurpose.ANY.getCode());

        for (CryptoServicePurpose purpose : CryptoServicePurpose.values())
        {
            isTrue("code does not round-trip through forCode() for " + purpose,
                purpose == CryptoServicePurpose.forCode(purpose.getCode()));
        }
    }

    private void testInvalidCodeRejected()
    {
        int[] badCodes = new int[]{-1, 10, 99, Integer.MIN_VALUE, Integer.MAX_VALUE};

        for (int badCode : badCodes)
        {
            try
            {
                CryptoServicePurpose.forCode(badCode);
                fail("forCode(" + badCode + ") should have thrown");
            }
            catch (IllegalArgumentException e)
            {
                // expected - an unrecognised code must fail loudly, not silently resolve
                // to some other purpose.
            }
        }
    }

    private void checkGeneralDigest(GeneralDigest digest, CryptoServicePurpose purpose, SecureRandom random)
        throws Exception
    {
        byte[] head = new byte[37];   // deliberately not block-aligned
        random.nextBytes(head);
        digest.update(head, 0, head.length);

        byte[] encoded = ((EncodableDigest)digest).getEncodedState();
        isEquals("wire byte does not match documented code for " + purpose,
            purpose.getCode(), encoded[encoded.length - 1] & 0xff);

        GeneralDigest restored = reconstructGeneralDigest(digest, encoded);
        isTrue("restored purpose mismatch for " + purpose,
            purpose == restored.cryptoServiceProperties().getPurpose());

        byte[] tail = new byte[19];
        random.nextBytes(tail);

        digest.update(tail, 0, tail.length);
        restored.update(tail, 0, tail.length);

        byte[] out1 = new byte[digest.getDigestSize()];
        byte[] out2 = new byte[restored.getDigestSize()];
        digest.doFinal(out1, 0);
        restored.doFinal(out2, 0);

        isTrue("digest diverged after state restore for " + purpose, Arrays.areEqual(out1, out2));
    }

    private GeneralDigest reconstructGeneralDigest(GeneralDigest original, byte[] encoded)
    {
        if (original instanceof SHA1Digest)
        {
            return new SHA1Digest(encoded);
        }
        if (original instanceof MD5Digest)
        {
            return new MD5Digest(encoded);
        }
        if (original instanceof SHA224Digest)
        {
            return new SHA224Digest(encoded);
        }
        if (original instanceof SHA256Digest)
        {
            return new SHA256Digest(encoded);
        }
        throw new IllegalStateException("unhandled digest type " + original.getClass());
    }

    private void checkLongDigest(LongDigest digest, CryptoServicePurpose purpose, SecureRandom random)
        throws Exception
    {
        byte[] head = new byte[131];  // deliberately not block-aligned (block size 128)
        random.nextBytes(head);
        digest.update(head, 0, head.length);

        byte[] encoded = ((EncodableDigest)digest).getEncodedState();
        isEquals("wire byte does not match documented code for " + purpose,
            purpose.getCode(), encoded[encoded.length - 1] & 0xff);

        LongDigest restored = reconstructLongDigest(digest, encoded);
        isTrue("restored purpose mismatch for " + purpose,
            purpose == restored.cryptoServiceProperties().getPurpose());

        byte[] tail = new byte[41];
        random.nextBytes(tail);

        digest.update(tail, 0, tail.length);
        restored.update(tail, 0, tail.length);

        byte[] out1 = new byte[digest.getDigestSize()];
        byte[] out2 = new byte[restored.getDigestSize()];
        digest.doFinal(out1, 0);
        restored.doFinal(out2, 0);

        isTrue("digest diverged after state restore for " + purpose, Arrays.areEqual(out1, out2));
    }

    private LongDigest reconstructLongDigest(LongDigest original, byte[] encoded)
    {
        if (original instanceof SHA384Digest)
        {
            return new SHA384Digest(encoded);
        }
        if (original instanceof SHA512tDigest)
        {
            return new SHA512tDigest(encoded);
        }
        if (original instanceof SHA512Digest)
        {
            return new SHA512Digest(encoded);
        }
        throw new IllegalStateException("unhandled digest type " + original.getClass());
    }

    private void checkKeccak(SHA3Digest digest, CryptoServicePurpose purpose, SecureRandom random)
        throws Exception
    {
        byte[] head = new byte[53];  // deliberately not rate-aligned
        random.nextBytes(head);
        digest.update(head, 0, head.length);

        byte[] encoded = digest.getEncodedState();
        isEquals("wire byte does not match documented code for " + purpose,
            purpose.getCode(), encoded[0] & 0xff);

        SHA3Digest restored = new SHA3Digest(encoded);
        isTrue("restored purpose mismatch for " + purpose,
            purpose == restored.cryptoServiceProperties().getPurpose());

        byte[] tail = new byte[23];
        random.nextBytes(tail);

        digest.update(tail, 0, tail.length);
        restored.update(tail, 0, tail.length);

        byte[] out1 = new byte[digest.getDigestSize()];
        byte[] out2 = new byte[restored.getDigestSize()];
        digest.doFinal(out1, 0);
        restored.doFinal(out2, 0);

        isTrue("digest diverged after state restore for " + purpose, Arrays.areEqual(out1, out2));
    }

    private void isEquals(String message, int a, int b)
    {
        if (a != b)
        {
            fail(message + ": expected " + a + " got " + b);
        }
    }

    public static void main(String[] args)
    {
        TestResult result = new CryptoServicePurposeStateTest().perform();

        System.out.println(result);
    }
}
