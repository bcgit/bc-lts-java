package org.bouncycastle.bcpg.sig;

import org.bouncycastle.bcpg.FingerprintUtil;
import org.bouncycastle.bcpg.KeyIdentifier;
import org.bouncycastle.bcpg.SignatureSubpacket;
import org.bouncycastle.bcpg.SignatureSubpacketTags;

/**
 * Signature Subpacket containing the key-id of the issuers signing (sub-) key.
 * If the version of that key is greater than 4, this subpacket MUST NOT be included in the signature.
 * For these keys, consider the {@link IssuerFingerprint} subpacket instead.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.3.5">
 *     RFC4880 - Issuer</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-issuer-key-id">
 *     RFC9580 - Issuer Key ID</a>
 */
public class IssuerKeyID 
    extends SignatureSubpacket
{
    protected static byte[] keyIDToBytes(
        long    keyId)
    {
        byte[]    data = new byte[8];
        FingerprintUtil.writeKeyID(keyId, data);
        return data;
    }
    
    public IssuerKeyID(
        boolean    critical,
        boolean    isLongLength,
        byte[]     data)
    {
        super(SignatureSubpacketTags.ISSUER_KEY_ID, critical, isLongLength, verifyData(data));
    }

    public IssuerKeyID(
        boolean    critical,
        long       keyID)
    {
        super(SignatureSubpacketTags.ISSUER_KEY_ID, critical, false, keyIDToBytes(keyID));
    }

    // RFC 9580 5.2.3.12: the Issuer Key ID body is an 8-octet key ID, which is what
    // FingerprintUtil.readKeyID requires of the body getKeyID() hands it.
    private static byte[] verifyData(byte[] data)
    {
        if (data.length < 8)
        {
            throw new IllegalArgumentException("Truncated issuer key-ID subpacket");
        }
        return data;
    }

    public long getKeyID()
    {
        return FingerprintUtil.readKeyID(data);
    }

    public KeyIdentifier getKeyIdentifier()
    {
        return new KeyIdentifier(getKeyID());
    }
}
