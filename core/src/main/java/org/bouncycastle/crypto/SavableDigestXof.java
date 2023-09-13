package org.bouncycastle.crypto;

import org.bouncycastle.crypto.digests.EncodableDigest;
import org.bouncycastle.util.Memoable;

/**
 * Extended digest which provides the ability to store state and
 * provide an encoding.
 */
public interface SavableDigestXof
    extends Xof, ExtendedDigest, EncodableDigest, Memoable
{
}
