package org.bouncycastle.cms.jcajce;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.PrivateKey;

import javax.crypto.Cipher;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.InputStreamWithMAC;
import org.bouncycastle.cms.RecipientOperator;
import org.bouncycastle.jcajce.io.CipherInputStream;
import org.bouncycastle.operator.InputAEADDecryptor;

/**
 * The KEM (RFC 9629 KEMRecipientInfo) recipient for CMS AuthEnvelopedData: decapsulates the
 * key-encryption key and returns an AEAD input decryptor (e.g. AES-GCM) that verifies the
 * authentication tag, the AuthEnveloped counterpart of {@link JceKEMEnvelopedRecipient}.
 * <p>
 * Built directly on {@link InputAEADDecryptor}, mirroring
 * {@link JceKeyTransAuthEnvelopedRecipient}, rather than on the CMSInputAEADDecryptor helper the
 * upstream version uses - that class is not part of this distribution.
 */
public class JceKEMAuthEnvelopedRecipient
    extends JceKEMRecipient
{
    public JceKEMAuthEnvelopedRecipient(PrivateKey recipientKey)
    {
        super(recipientKey);
    }

    public RecipientOperator getRecipientOperator(AlgorithmIdentifier keyEncryptionAlgorithm, final AlgorithmIdentifier contentEncryptionAlgorithm, byte[] encryptedContentEncryptionKey)
        throws CMSException
    {
        Key secretKey = extractSecretKey(keyEncryptionAlgorithm, contentEncryptionAlgorithm, encryptedContentEncryptionKey);

        final Cipher dataCipher = contentHelper.createContentCipher(secretKey, contentEncryptionAlgorithm);

        return new RecipientOperator(new InputAEADDecryptor()
        {
            private InputStream inputStream;

            public AlgorithmIdentifier getAlgorithmIdentifier()
            {
                return contentEncryptionAlgorithm;
            }

            public InputStream getInputStream(InputStream dataIn)
            {
                inputStream = dataIn;
                return new CipherInputStream(dataIn, dataCipher);
            }

            public OutputStream getAADStream()
            {
                return new JceAADStream(dataCipher);
            }

            public byte[] getMAC()
            {
                if (inputStream instanceof InputStreamWithMAC)
                {
                    return ((InputStreamWithMAC)inputStream).getMAC();
                }
                return null;
            }
        });
    }
}
