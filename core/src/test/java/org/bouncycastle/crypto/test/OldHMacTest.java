package org.bouncycastle.crypto.test;

import java.security.SecureRandom;

import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.macs.OldHMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * OldHMac's sole functional constructor - OldHMac(Digest) - was missing entirely from this
 * checkout (only the implicit no-arg constructor remained, which leaves the underlying digest
 * null and so cannot be used at all). Restored alongside the existing no-arg constructor so
 * existing compiled callers of either signature keep working. This test exercises the restored
 * constructor: the negative cases (key/message/digest sensitivity) rule out a MAC that has been
 * accidentally stubbed to a constant or an identity function, and the chunking matrix confirms
 * the block-buffering path behind the underlying digest is exercised correctly either way.
 */
public class OldHMacTest
    extends SimpleTest
{
    public String getName()
    {
        return "OldHMac";
    }

    public void performTest()
        throws Exception
    {
        SecureRandom random = new SecureRandom();

        checkTransform(new OldHMac(new MD5Digest()), new OldHMac(new MD5Digest()), random);
        checkTransform(new OldHMac(new SHA1Digest()), new OldHMac(new SHA1Digest()), random);
    }

    private void checkTransform(Mac mac1, Mac mac2, SecureRandom random)
        throws Exception
    {
        byte[] key = new byte[37];
        random.nextBytes(key);

        byte[] message = new byte[173];    // deliberately not block-aligned (block size 64)
        random.nextBytes(message);

        byte[] oneShot = mac(mac1, key, message);

        // determinism: same key + message -> same tag
        isTrue("MAC not deterministic", Arrays.areEqual(oneShot, mac(mac1, key, message)));

        // the transform actually transforms - a stubbed/identity implementation would fail this
        isTrue("MAC looks like an identity/constant function", !Arrays.areEqual(oneShot, message));

        // flipping a message byte must change the tag
        byte[] tamperedMessage = Arrays.clone(message);
        tamperedMessage[message.length / 2] ^= 0x01;
        isTrue("tag unchanged after message bit flip",
            !Arrays.areEqual(oneShot, mac(mac1, key, tamperedMessage)));

        // a different key must change the tag
        byte[] otherKey = Arrays.clone(key);
        otherKey[0] ^= 0x01;
        isTrue("tag unchanged after key change", !Arrays.areEqual(oneShot, mac(mac1, otherKey, message)));

        // vary the chunking: byte-by-byte, adversarial block-boundary offsets, and random splits
        // must all be byte-identical to the one-shot result.
        isTrue("byte-by-byte chunking diverged", Arrays.areEqual(oneShot, macByteByByte(mac2, key, message)));

        int blockSize = 64;
        int[][] chunkPlans = new int[][]{
            {blockSize - 1, message.length - (blockSize - 1)},
            {blockSize, message.length - blockSize},
            {blockSize + 1, message.length - (blockSize + 1)},
        };
        for (int planNo = 0; planNo < chunkPlans.length; planNo++)
        {
            isTrue("adversarial-offset chunking diverged for plan " + planNo,
                Arrays.areEqual(oneShot, macChunked(mac2, key, message, chunkPlans[planNo])));
        }

        // random split
        int split = 1 + random.nextInt(message.length - 1);
        isTrue("random-split chunking diverged",
            Arrays.areEqual(oneShot, macChunked(mac2, key, message, new int[]{split, message.length - split})));
    }

    private byte[] mac(Mac mac, byte[] key, byte[] message)
    {
        mac.init(new KeyParameter(key));
        mac.update(message, 0, message.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    private byte[] macByteByByte(Mac mac, byte[] key, byte[] message)
    {
        mac.init(new KeyParameter(key));
        for (int i = 0; i != message.length; i++)
        {
            mac.update(message[i]);
        }
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    private byte[] macChunked(Mac mac, byte[] key, byte[] message, int[] chunkLengths)
    {
        mac.init(new KeyParameter(key));
        int off = 0;
        for (int len : chunkLengths)
        {
            mac.update(message, off, len);
            off += len;
        }
        isTrue("chunk plan does not cover the whole message", off == message.length);
        byte[] out = new byte[mac.getMacSize()];
        mac.doFinal(out, 0);
        return out;
    }

    public static void main(String[] args)
    {
        TestResult result = new OldHMacTest().perform();

        System.out.println(result);
    }
}
