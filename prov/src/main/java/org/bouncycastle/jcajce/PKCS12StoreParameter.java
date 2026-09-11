package org.bouncycastle.jcajce;

import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.LoadStoreParameter;
import java.security.KeyStore.ProtectionParameter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PBMAC1Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.util.Arrays;

/**
 * LoadStoreParameter to allow for additional config with PKCS12 files.
 * <p>
 * Note: if you want a straight DER encoding of a PKCS#12 file you should use this.
 * </p>
 */
public class PKCS12StoreParameter
    implements LoadStoreParameter
{
    private final OutputStream out;
    private final ProtectionParameter protectionParameter;
    private final boolean forDEREncoding;
    private final boolean overwriteFriendlyName;
    private final AlgorithmIdentifier macAlgorithm;
    private final boolean useISO8859d1ForDecryption;

    /**
     * Builder for the PBMAC1 integrity-MAC algorithm identifier of a PKCS#12 file, with PBKDF2 as the
     * key-derivation function, as specified by
     * <a href="https://www.rfc-editor.org/rfc/rfc9579">RFC 9579</a>. Pass the result to
     * {@link Builder#setMacAlgorithm(AlgorithmIdentifier)}.
     * <p>
     * The defaults are 16384 iterations, a 64-octet derived key, HMAC-SHA-256 as the PBKDF2 PRF and
     * HMAC-SHA-512 as the message-authentication scheme. A salt has no default and must be supplied.
     * </p>
     */
    public static class PBMAC1WithPBKDF2Builder
    {
        private int iterationCount = 16384;
        private byte[] salt = null;
        private int keySizeInOctets = 64;
        private ASN1ObjectIdentifier prf = PKCSObjectIdentifiers.id_hmacWithSHA256;
        private ASN1ObjectIdentifier mac = PKCSObjectIdentifiers.id_hmacWithSHA512;

        PBMAC1WithPBKDF2Builder()
        {

        }

        /**
         * Set the PBKDF2 iteration count. The default is 16384.
         *
         * @param iterationCount the iteration count to derive the MAC key with.
         * @return this builder.
         */
        public PBMAC1WithPBKDF2Builder setIterationCount(int iterationCount)
        {
            this.iterationCount = iterationCount;

            return this;
        }

        /**
         * Set the PBKDF2 salt. There is no default - {@link #build()} fails without one.
         *
         * @param salt the salt to derive the MAC key with; the array is copied.
         * @return this builder.
         */
        public PBMAC1WithPBKDF2Builder setSalt(byte[] salt)
        {
            this.salt = Arrays.clone(salt);

            return this;
        }

        /**
         * Set the length of the MAC key PBKDF2 derives, <b>in octets</b> - this is the PBKDF2-params
         * keyLength field, which RFC 8018 app. A.2 defines in octets rather than bits.
         * <p>
         * RFC 9579 sec. 5 has it match the output size of the message-authentication scheme set by
         * {@link #setMac(ASN1ObjectIdentifier)}: 64 for the default HMAC-SHA-512, 32 for HMAC-SHA-256.
         * Sec. 9 of the same document asks that a length below 20 octets be rejected, and BC does so
         * when the MAC is derived. The default is 64.
         * </p>
         *
         * @param keySizeInOctets the length in octets of the key to derive.
         * @return this builder.
         */
        public PBMAC1WithPBKDF2Builder setKeySize(int keySizeInOctets)
        {
            this.keySizeInOctets = keySizeInOctets;

            return this;
        }

        /**
         * Set the PBKDF2 pseudo-random function. The default is HMAC-SHA-256, which RFC 9579 sec. 5
         * requires every implementation to support.
         *
         * @param prf OID of the PRF to derive the MAC key with.
         * @return this builder.
         */
        public PBMAC1WithPBKDF2Builder setPrf(ASN1ObjectIdentifier prf)
        {
            this.prf = prf;

            return this;
        }

        /**
         * Set the message-authentication scheme the derived key is used with. The default is
         * HMAC-SHA-512. Changing it means changing {@link #setKeySize(int)} to match its output size.
         *
         * @param mac OID of the HMAC to authenticate the file with.
         * @return this builder.
         */
        public PBMAC1WithPBKDF2Builder setMac(ASN1ObjectIdentifier mac)
        {
            this.mac = mac;

            return this;
        }

        /**
         * Build the PBMAC1 algorithm identifier.
         *
         * @return an AlgorithmIdentifier for id-PBMAC1 carrying the configured PBMAC1-params.
         * @throws IllegalStateException if no salt has been set.
         */
        public AlgorithmIdentifier build()
        {
            if (salt == null)
            {
                throw new IllegalStateException("salt must be non-null");
            }

            PBKDF2Params pbkdf2Params = new PBKDF2Params(salt, iterationCount, keySizeInOctets,
                new AlgorithmIdentifier(prf));
            AlgorithmIdentifier keyDevFunc = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBKDF2, pbkdf2Params);
            AlgorithmIdentifier authScheme = new AlgorithmIdentifier(mac);
            PBMAC1Params pbmac1Params = new PBMAC1Params(keyDevFunc, authScheme);

            return new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBMAC1, pbmac1Params);
        }
    }

    /**
     * Return a builder for an RFC 9579 PBMAC1 algorithm identifier using PBKDF2.
     *
     * @return a new {@link PBMAC1WithPBKDF2Builder}.
     */
    public static PBMAC1WithPBKDF2Builder pbmac1WithPBKDF2Builder()
    {
        return new PBMAC1WithPBKDF2Builder();
    }

    public static class Builder
    {
        private final OutputStream out;
        private final ProtectionParameter protectionParameter;
        private boolean forDEREncoding = true;
        private boolean overwriteFriendlyName = true;
        private boolean useISO8859d1ForDecryption = false;
        private AlgorithmIdentifier macAlgorithm = new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE);

        private Builder(OutputStream out, ProtectionParameter protectionParameter)
        {
            this.out = out;
            this.protectionParameter = protectionParameter;
        }

        public Builder setDEREncoding(boolean enable)
        {
            this.forDEREncoding = enable;

            return this;
        }

        public Builder setOverwriteFriendlyName(boolean enable)
        {
            this.overwriteFriendlyName = enable;

            return this;
        }

        public Builder setUseISO8859d1ForDecryption(boolean enable)
        {
            this.useISO8859d1ForDecryption = enable;

            return this;
        }

        public Builder setMacAlgorithm(AlgorithmIdentifier macAlgorithm)
        {
            this.macAlgorithm = macAlgorithm;

            return this;
        }

        public PKCS12StoreParameter build()
        {
            return new PKCS12StoreParameter(out, protectionParameter, forDEREncoding, overwriteFriendlyName, macAlgorithm, useISO8859d1ForDecryption);
        }
    }

    public static Builder builder(OutputStream out, char[] password)
    {
        return builder(out, new KeyStore.PasswordProtection(password));
    }

    public static Builder builder(OutputStream out, ProtectionParameter protectionParameter)
    {
        return new Builder(out, protectionParameter);
    }

    public PKCS12StoreParameter(OutputStream out, char[] password)
    {
        this(out, password, false);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter)
    {
        this(out, protectionParameter, false, true);
    }

    public PKCS12StoreParameter(OutputStream out, char[] password, boolean forDEREncoding)
    {
        this(out, new KeyStore.PasswordProtection(password), forDEREncoding, true);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding)
    {
        this(out, protectionParameter, forDEREncoding, true);
    }

    public PKCS12StoreParameter(OutputStream out, char[] password, boolean forDEREncoding, boolean overwriteFriendlyName)
    {
        this(out, new KeyStore.PasswordProtection(password), forDEREncoding, overwriteFriendlyName);
    }

    public PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding, boolean overwriteFriendlyName)
    {
        this(out, protectionParameter, forDEREncoding, overwriteFriendlyName, new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1, DERNull.INSTANCE), false);
    }

    private PKCS12StoreParameter(OutputStream out, ProtectionParameter protectionParameter, boolean forDEREncoding, boolean overwriteFriendlyName, AlgorithmIdentifier macAlgorithm, boolean useISO8859d1ForDecryption)
    {
        this.out = out;
        this.protectionParameter = protectionParameter;
        this.forDEREncoding = forDEREncoding;
        this.overwriteFriendlyName = overwriteFriendlyName;
        this.macAlgorithm = macAlgorithm;
        this.useISO8859d1ForDecryption = useISO8859d1ForDecryption;
    }

    public OutputStream getOutputStream()
    {
        return out;
    }

    public ProtectionParameter getProtectionParameter()
    {
        return protectionParameter;
    }

    /**
     * Return whether the KeyStore used with this parameter should be DER encoded on saving.
     *
     * @return true for straight DER encoding, false otherwise,
     */
    public boolean isForDEREncoding()
    {
        return forDEREncoding;
    }

    /**
     * Return whether the KeyStore used with this parameter should overwrite friendlyName
     * when friendlyName is not present or does not equal the same name as alias
     *
     * @return true (default) to overwrite friendlyName, false otherwise,
     */
    public boolean isOverwriteFriendlyName()
    {
        return overwriteFriendlyName;
    }

    public AlgorithmIdentifier getMacAlgorithm()
    {
        return macAlgorithm;
    }

    public boolean useISO8859d1ForDecryption()
    {
        return useISO8859d1ForDecryption;
    }
}
