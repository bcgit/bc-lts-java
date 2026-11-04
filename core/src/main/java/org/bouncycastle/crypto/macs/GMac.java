package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.GCMModeCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;


/**
 * The GMAC specialisation of Galois/Counter mode (GCM) detailed in NIST Special Publication
 * 800-38D.
 * <p>
 * GMac is an invocation of the GCM mode where no data is encrypted (i.e. all input data to the Mac
 * is processed as additional authenticated data with the underlying GCM block cipher).
 * <p>
 * Once a tag has been produced, the MAC can be used again under the same key and nonce only
 * over the same data, which gets the same tag. Different data is refused, as two tags under one
 * nonce would give away the GHASH key. To MAC different data, initialise with a new nonce.
 * </p>
 */
public class GMac implements Mac
{
    private final GCMModeCipher cipher;
    private int macSizeBits;

    // the nonce and initial associated text of the last successful init.
    private byte[] nonce;
    private byte[] initialAssociatedText;
    private boolean initFailed;
    // the tag produced under the current nonce, once there is one.
    private byte[] lastTag;
    // true while the cipher is set up, in decrypt mode, to check the data against lastTag.
    private boolean verifying;

    /**
     * Creates a GMAC based on the operation of a block cipher in GCM mode.
     * <p>
     * This will produce an authentication code the length of the block size of the cipher.
     * 
     * @param cipher
     *            the cipher to be used in GCM mode to generate the MAC.
     */
    public GMac(final GCMModeCipher cipher)
    {
        // use of this confused flow analyser in some earlier JDKs
        this.cipher = cipher;
        this.macSizeBits = 128;
    }

    /**
     * Creates a GMAC based on the operation of a 128 bit block cipher in GCM mode.
     * 
     * @param macSizeBits
     *            the mac size to generate, in bits. Must be a multiple of 8 and &gt;= 32 and &lt;= 128.
     *            Sizes less than 96 are not recommended, but are supported for specialized applications.
     * @param cipher
     *            the cipher to be used in GCM mode to generate the MAC.
     */
    public GMac(final GCMModeCipher cipher, final int macSizeBits)
    {
        this.cipher = cipher;
        this.macSizeBits = macSizeBits;
    }

    /**
     * Initialises the GMAC - requires either a {@link ParametersWithIV} providing a
     * {@link KeyParameter} and a nonce, or an {@link AEADParameters} carrying the key, nonce and
     * desired MAC size. When {@link AEADParameters} are supplied the MAC size they carry overrides
     * the one passed to the constructor (this is the form used by RFC 9044 AES-GMAC, whose
     * GMACParameters allow a 12 to 16 octet tag).
     */
    public void init(final CipherParameters params) throws IllegalArgumentException
    {
        // until this init succeeds, nothing is processed.
        this.initFailed = true;
        this.lastTag = null;
        this.verifying = false;

        final AEADParameters gcmParams;
        if (params instanceof AEADParameters)
        {
            gcmParams = (AEADParameters)params;

            this.macSizeBits = gcmParams.getMacSize();
        }
        else if (params instanceof ParametersWithIV)
        {
            final ParametersWithIV param = (ParametersWithIV)params;

            final byte[] iv = param.getIV();
            final KeyParameter keyParam = (KeyParameter)param.getParameters();

            gcmParams = new AEADParameters(keyParam, macSizeBits, iv);
        }
        else
        {
            throw new IllegalArgumentException("GMAC requires ParametersWithIV or AEADParameters");
        }

        // GCM is always operated in encrypt mode to calculate MAC
        cipher.init(true, gcmParams);

        this.nonce = gcmParams.getNonce();
        this.initialAssociatedText = gcmParams.getAssociatedText();
        this.initFailed = false;
    }

    public String getAlgorithmName()
    {
        return cipher.getUnderlyingCipher().getAlgorithmName() + "-GMAC";
    }

    public int getMacSize()
    {
        return macSizeBits / 8;
    }

    public void update(byte in) throws IllegalStateException
    {
        prepare();
        cipher.processAADByte(in);
    }

    public void update(byte[] in, int inOff, int len)
        throws DataLengthException, IllegalStateException
    {
        prepare();
        cipher.processAADBytes(in, inOff, len);
    }

    public int doFinal(byte[] out, int outOff)
        throws DataLengthException, IllegalStateException
    {
        prepare();

        if (lastTag == null)
        {
            try
            {
                int len = cipher.doFinal(out, outOff);
                lastTag = Arrays.copyOfRange(out, outOff, outOff + len);
                return len;
            }
            catch (InvalidCipherTextException e)
            {
                // Impossible in encrypt mode
                throw new IllegalStateException(e.toString());
            }
        }

        if (out.length - outOff < lastTag.length)
        {
            throw new OutputLengthException("Output buffer too short");
        }

        // A tag has already been given out under this nonce. Check this data against it, in
        // decrypt mode, so the tag of different data is never computed into the caller's hands.
        byte[] none = new byte[lastTag.length];
        try
        {
            cipher.processBytes(lastTag, 0, lastTag.length, none, 0);
            cipher.doFinal(none, 0);
        }
        catch (InvalidCipherTextException e)
        {
            cipher.reset();
            throw new IllegalStateException("GMAC cannot be reused with the same nonce over different data");
        }

        System.arraycopy(lastTag, 0, out, outOff, lastTag.length);
        return lastTag.length;
    }

    public void reset()
    {
        cipher.reset();
    }

    private void prepare()
    {
        if (initFailed)
        {
            throw new IllegalStateException("GMAC needs to be initialised");
        }

        if (lastTag != null && !verifying)
        {
            // same key (null reuses it) and nonce: decryption is not guarded against nonce reuse,
            // and computes nothing that is given out.
            cipher.init(false, new AEADParameters(null, lastTag.length * 8, nonce, initialAssociatedText));
            verifying = true;
        }
    }
}
