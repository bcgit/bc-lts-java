package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;

/**
 * Marker interface for raw symmetric block cipher engines that operate
 * in ECB (Electronic Codebook) mode. Engines that implement this interface
 * process one block at a time without chaining state between blocks, which
 * makes them suitable as the underlying primitive for higher-level modes
 * such as CBC, CTR, GCM, CTS, etc.
 */
public interface ECBModeCipher
    extends BlockCipher
{
}
