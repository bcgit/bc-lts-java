package org.bouncycastle.crypto.modes;

import java.security.SecureRandom;
import java.util.Random;

import junit.framework.TestCase;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Arrays;

/**
 * The CCM payload length limit (SP 800-38C A.1: fewer than 2^(8q) octets) on every CCM in the
 * distribution: the java CCMBlockCipher, the default one (native where the native layer is loaded),
 * the java packet cipher and the default packet cipher. All four must agree.
 * <ul>
 * <li>On decryption the limit applies to the payload, not to the payload plus the tag: the
 * native CCM and both packet ciphers counted the tag, so refused the largest payloads that
 * encrypt fine.</li>
 * <li>An over-limit ciphertext is refused before its tag is checked, whatever the tag length.</li>
 * <li>The maximum payload gives the same ciphertext on every engine, so the B0 length field
 * is encoded alike.</li>
 * </ul>
 */
public class CCMPayloadLimitTest
    extends TestCase
{
    private static final long SEED = new SecureRandom().nextLong();
    private static final String TOO_LARGE = "CCM packet too large for choice of q";

    private interface Engine
    {
        String name();

        byte[] process(boolean forEncryption, AEADParameters params, byte[] in)
            throws Exception;
    }

    private static Engine blockCipher(final String name, final boolean java)
    {
        return new Engine()
        {
            public String name()
            {
                return name;
            }

            public byte[] process(boolean forEncryption, AEADParameters params, byte[] in)
                throws Exception
            {
                CCMModeCipher ccm = java ? new CCMBlockCipher(AESEngine.newInstance())
                    : CCMBlockCipher.newInstance(AESEngine.newInstance());
                ccm.init(forEncryption, params);
                return ccm.processPacket(in, 0, in.length);
            }
        };
    }

    private static Engine packetCipher(final String name, final boolean java)
    {
        return new Engine()
        {
            public String name()
            {
                return name;
            }

            public byte[] process(boolean forEncryption, AEADParameters params, byte[] in)
                throws Exception
            {
                AESCCMModePacketCipher ccm = java ? new AESCCMPacketCipher() : AESCCMPacketCipher.newInstance();
                byte[] out = new byte[ccm.getOutputSize(forEncryption, params, in.length)];
                int len = ccm.processPacket(forEncryption, params, in, 0, in.length, out, 0);
                return Arrays.copyOfRange(out, 0, len);
            }
        };
    }

    private static final Engine[] ENGINES = {
        blockCipher("java CCMBlockCipher", true),
        blockCipher("default CCMBlockCipher", false),
        packetCipher("java packet cipher", true),
        packetCipher("default packet cipher", false)
    };

    private Random random;
    private KeyParameter key;

    public void setUp()
    {
        // seeded so a failing run can be reproduced from the seed in the message.
        random = new Random(SEED);
        key = new KeyParameter(randomBytes(16 + 8 * random.nextInt(3)));
    }

    public void testMaximumPayloadAgrees()
        throws Exception
    {
        // a 13 octet nonce gives q = 2: the payload is limited to 2^16 - 1 octets.
        byte[] nonce = randomBytes(13);
        byte[] max = randomBytes((1 << 16) - 1);

        for (int macSizeBits = 32; macSizeBits <= 128; macSizeBits += 32)
        {
            AEADParameters params = new AEADParameters(key, macSizeBits, nonce);
            byte[] expected = null;

            for (int i = 0; i != ENGINES.length; i++)
            {
                Engine e = ENGINES[i];
                byte[] ct = e.process(true, params, max);

                assertEquals(msg(e, macSizeBits, "ciphertext length"), max.length + macSizeBits / 8, ct.length);
                if (expected == null)
                {
                    expected = ct;
                }
                else
                {
                    assertTrue(msg(e, macSizeBits, "ciphertext differs from " + ENGINES[0].name()),
                        Arrays.areEqual(expected, ct));
                }

                assertTrue(msg(e, macSizeBits, "maximum payload round trip"),
                    Arrays.areEqual(max, e.process(false, params, ct)));
            }

            // the largest ciphertext is not refused for its length: a damaged tag reaches the tag check.
            byte[] damaged = Arrays.clone(expected);
            damaged[damaged.length - 1] ^= 1;
            for (int i = 0; i != ENGINES.length; i++)
            {
                Engine e = ENGINES[i];
                try
                {
                    e.process(false, params, damaged);
                    fail(msg(e, macSizeBits, "damaged tag accepted"));
                }
                catch (Exception ex)
                {
                    assertFalse(msg(e, macSizeBits, "maximum payload refused for its length"), isTooLarge(ex));
                    assertTrue(msg(e, macSizeBits, "damaged tag not reported as a tag failure: " + ex),
                        isTagFailure(ex));
                }
            }
        }
    }

    public void testOverLimitPayloadRefused()
        throws Exception
    {
        for (int nonceLen = 13; nonceLen >= 12; nonceLen--)
        {
            // q = 2 or 3: the limit is 2^16 or 2^24 octets.
            int limit = 1 << ((15 - nonceLen) * 8);
            byte[] nonce = randomBytes(nonceLen);
            byte[] over = new byte[limit];

            for (int macSizeBits = 32; macSizeBits <= 128; macSizeBits += 16)
            {
                AEADParameters params = new AEADParameters(key, macSizeBits, nonce);
                byte[] overCt = new byte[limit + macSizeBits / 8];

                for (int i = 0; i != ENGINES.length; i++)
                {
                    Engine e = ENGINES[i];
                    try
                    {
                        e.process(true, params, over);
                        fail(msg(e, macSizeBits, "over-limit payload encrypted, nonce " + nonceLen));
                    }
                    catch (Exception ex)
                    {
                        assertTrue(msg(e, macSizeBits, "over-limit encryption: " + ex), isTooLarge(ex));
                    }

                    try
                    {
                        e.process(false, params, overCt);
                        fail(msg(e, macSizeBits, "over-limit ciphertext decrypted, nonce " + nonceLen));
                    }
                    catch (Exception ex)
                    {
                        assertTrue(msg(e, macSizeBits, "over-limit ciphertext not refused before the tag check: " + ex),
                            isTooLarge(ex));
                    }
                }
            }
        }
    }

    private static boolean isTooLarge(Throwable ex)
    {
        for (Throwable t = ex; t != null; t = t.getCause())
        {
            if (t.getMessage() != null && t.getMessage().startsWith(TOO_LARGE))
            {
                return true;
            }
        }
        return false;
    }

    private static boolean isTagFailure(Throwable ex)
    {
        if (ex instanceof InvalidCipherTextException)
        {
            return true;
        }
        if (ex instanceof PacketCipherException)
        {
            return ((PacketCipherException)ex).getReason() == PacketCipherException.Reason.INVALID_CIPHERTEXT;
        }
        return false;
    }

    private static String msg(Engine e, int macSizeBits, String what)
    {
        return e.name() + ", tag " + macSizeBits + " bits: " + what + " (seed " + SEED + ")";
    }

    private byte[] randomBytes(int len)
    {
        byte[] b = new byte[len];
        random.nextBytes(b);
        return b;
    }
}
