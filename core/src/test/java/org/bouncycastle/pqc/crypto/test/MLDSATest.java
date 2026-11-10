package org.bouncycastle.pqc.crypto.test;

import junit.framework.TestCase;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithContext;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.MLDSASigner;
import org.bouncycastle.util.Strings;
import org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator;
import org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.MLDSAParameters;
import org.bouncycastle.crypto.params.MLDSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.MLDSAPublicKeyParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.test.TestResourceFinder;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.test.FixedSecureRandom;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.HashMLDSASigner;

public class MLDSATest
    extends TestCase
{
    private static final Map<String, MLDSAParameters> PARAMETERS_MAP = new HashMap<String, MLDSAParameters>()
    {
        {
            put("ML-DSA-44", MLDSAParameters.ml_dsa_44);
            put("ML-DSA-65", MLDSAParameters.ml_dsa_65);
            put("ML-DSA-87", MLDSAParameters.ml_dsa_87);
        }
    };

    private static final MLDSAParameters[] PARAMETER_SETS = new MLDSAParameters[]
    {
        MLDSAParameters.ml_dsa_44,
        MLDSAParameters.ml_dsa_65,
        MLDSAParameters.ml_dsa_87,
    };

    public void testConsistency() throws Exception
    {
        SecureRandom random = new SecureRandom();

        MLDSAKeyPairGenerator kpg = new MLDSAKeyPairGenerator();

        for (int idx = 0; idx != PARAMETER_SETS.length; idx++)
        {
            MLDSAParameters parameters = PARAMETER_SETS[idx];
            kpg.init(new MLDSAKeyGenerationParameters(random, parameters));

            int msgSize = 0;
            do
            {
                byte[] msg = new byte[msgSize];

                for (int i = 0; i < 2; ++i)
                {
                    AsymmetricCipherKeyPair kp = kpg.generateKeyPair();

                    MLDSASigner signer = new MLDSASigner();

                    for (int j = 0; j < 2; ++j)
                    {
                        random.nextBytes(msg);

                        // sign
                        signer.init(true, new ParametersWithRandom(kp.getPrivate(), random));
                        signer.update(msg, 0, msg.length);
                        byte[] signature = signer.generateSignature();

                        // verify
                        signer.init(false, kp.getPublic());
                        signer.update(msg, 0, msg.length);
                        boolean shouldVerify = signer.verifySignature(signature);

                        assertTrue("count = " + i, shouldVerify);
                    }
                }

                msgSize += msgSize < 128 ? 1 : 17;
            }
            while (msgSize <= 2048);
        }
    }

    public void testCalculateMuVerify()
        throws Exception
    {
        // the signer under test is the org.bouncycastle.crypto one, so its keys come from that stack's generator
        org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator kpGen = new org.bouncycastle.crypto.generators.MLDSAKeyPairGenerator();
        kpGen.init(new org.bouncycastle.crypto.params.MLDSAKeyGenerationParameters(new SecureRandom(), org.bouncycastle.crypto.params.MLDSAParameters.ml_dsa_65));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

        byte[][] messages = { new byte[0], Strings.toByteArray("Hello World!") };
        byte[][] contexts = { null, Strings.toByteArray("context") };

        for (int c = 0; c != contexts.length; c++)
        {
            for (int m = 0; m != messages.length; m++)
            {
                byte[] message = messages[m];
                CipherParameters priv = contexts[c] == null ? (CipherParameters)kp.getPrivate() : new ParametersWithContext(kp.getPrivate(), contexts[c]);
                CipherParameters pub = contexts[c] == null ? (CipherParameters)kp.getPublic() : new ParametersWithContext(kp.getPublic(), contexts[c]);

                MLDSASigner signer = new MLDSASigner();
                signer.init(true, priv);
                signer.update(message, 0, message.length);
                byte[] mu = signer.generateMu();
                signer.update(message, 0, message.length);
                byte[] signature = signer.generateSignature();

                MLDSASigner verifier = new MLDSASigner();
                verifier.init(false, pub);
                verifier.update(message, 0, message.length);
                assertTrue("mu rejected, message length " + message.length, verifier.verifyMu(mu));

                byte[] flipped = Arrays.clone(mu);
                flipped[0] ^= 1;
                verifier.update(message, 0, message.length);
                assertFalse(verifier.verifyMu(flipped));

                // checking a mu must leave the verifier able to check an ordinary signature
                verifier.update(message, 0, message.length);
                assertTrue(verifier.verifySignature(signature));

                try
                {
                    verifier.verifyMu(new byte[3]);
                    fail("short mu accepted");
                }
                catch (DataLengthException e)
                {
                    assertEquals("mu value must be 64 bytes", e.getMessage());
                }
                verifier.update(message, 0, message.length);
                assertTrue(verifier.verifyMu(mu));
            }
        }
    }

    public void testKeyGen()
        throws IOException
    {
        String[] files = new String[]{
            "keyGen_ML-DSA-44.txt",
            "keyGen_ML-DSA-65.txt",
            "keyGen_ML-DSA-87.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        byte[] seed = Hex.decode((String)buf.get("seed"));
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] sk = Hex.decode((String)buf.get("sk"));

                        FixedSecureRandom random = new FixedSecureRandom(seed);
                        MLDSAParameters parameters = PARAMETER_SETS[fileIndex];

                        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
                        kpGen.init(new MLDSAKeyGenerationParameters(random, parameters));

                        //
                        // Generate keys and test.
                        //
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        MLDSAPublicKeyParameters pubParams = (MLDSAPublicKeyParameters)PublicKeyFactory.createKey(
                            SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                        MLDSAPrivateKeyParameters privParams = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(
                            PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));

                        assertTrue(name + ": public key", Arrays.areEqual(pk, pubParams.getEncoded()));
                        assertTrue(name + ": secret key", Arrays.areEqual(sk, privParams.getEncoded()));
                    }
                    buf.clear();
                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
    }

    public void testSigGen()
        throws IOException
    {
        String[] files = new String[]{
            "sigGen_ML-DSA-44.txt",
            "sigGen_ML-DSA-65.txt",
            "sigGen_ML-DSA-87.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        boolean deterministic = !buf.containsKey("rnd");
                        byte[] sk = Hex.decode((String)buf.get("sk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));
                        byte[] rnd = new byte[32];
                        if (!deterministic)
                        {
                            rnd = Hex.decode((String)buf.get("rnd"));
                        }

                        MLDSAParameters parameters = PARAMETER_SETS[fileIndex];

                        MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(parameters, sk, null);

                        // sign
                        InternalMLDSASigner signer = new InternalMLDSASigner();

                        signer.init(true, privParams);

                        byte[] sigGenerated = signer.internalGenerateSignature(message, rnd);

                        assertTrue(Arrays.areEqual(sigGenerated, signature));
                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
    }

    public void testSigVer()
        throws IOException
    {
        String[] files = new String[]{
            "sigVer_ML-DSA-44.txt",
            "sigVer_ML-DSA-65.txt",
            "sigVer_ML-DSA-87.txt",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            InputStream src = TestResourceFinder.findTestResource("pqc/crypto/dilithium/acvp", name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        boolean testPassed = TestUtils.parseBoolean((String)buf.get("testPassed"));
                        String reason = (String)buf.get("reason");
                        byte[] pk = Hex.decode((String)buf.get("pk"));
                        byte[] message = Hex.decode((String)buf.get("message"));
                        byte[] signature = Hex.decode((String)buf.get("signature"));

                        MLDSAParameters parameters = PARAMETER_SETS[fileIndex];

                        MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(parameters, pk);

                        InternalMLDSASigner verifier = new InternalMLDSASigner();
                        verifier.init(false, pubParams);

                        boolean ver = verifier.internalVerifySignature(message, signature);
                        assertEquals("expected " + testPassed + " " + reason, testPassed, ver);
                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
        }
    }

    public void testRNG()
    {
        String temp = "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1";
        byte[] seed = Hex.decode(temp);

        NISTSecureRandom r = new NISTSecureRandom(seed, null);

        String testBytesString = "7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2D";
        byte[] testBytes = Hex.decode(testBytesString);

        byte[] randBytes = new byte[testBytes.length];
        r.nextBytes(randBytes);

        assertTrue(Arrays.areEqual(randBytes, testBytes));
    }

    public void testKeyGenCombinedVectorSet()
        throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mldsa", "ML-DSA-keyGen.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.startsWith("#"))
            {
                continue;
            }
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    byte[] seed = Hex.decode((String)buf.get("seed"));
                    byte[] pk = Hex.decode((String)buf.get("pk"));
                    byte[] sk = Hex.decode((String)buf.get("sk"));

                    FixedSecureRandom random = new FixedSecureRandom(seed);
                    MLDSAParameters parameters = (MLDSAParameters)PARAMETERS_MAP.get((String)buf.get("parameterSet"));

                    MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
                    kpGen.init(new MLDSAKeyGenerationParameters(random, parameters));

                    //
                    // Generate keys and test.
                    //
                    AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                    MLDSAPublicKeyParameters pubParams = (MLDSAPublicKeyParameters)PublicKeyFactory.createKey(
                        SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(kp.getPublic()));
                    MLDSAPrivateKeyParameters privParams = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(
                        PrivateKeyInfoFactory.createPrivateKeyInfo(kp.getPrivate()));

                    assertTrue(Arrays.areEqual(pk, pubParams.getEncoded()));
                    assertTrue(Arrays.areEqual(sk, privParams.getEncoded()));
                }
                buf.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    public void testSigGenCombinedVectorSet()
        throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mldsa", "ML-DSA-sigGen.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.startsWith("#"))
            {
                continue;
            }
            if (line.length() == 0)
            {
                if (buf.size() > 0)
                {
                    boolean deterministic = TestUtils.parseBoolean((String)buf.get("deterministic"));
                    byte[] sk = Hex.decode((String)buf.get("sk"));
                    byte[] message = Hex.decode((String)buf.get("message"));
                    byte[] signature = Hex.decode((String)buf.get("signature"));
                    byte[] rnd = null;
                    if (!deterministic)
                    {
                        rnd = Hex.decode((String)buf.get("rnd"));
                    }
                    else
                    {
                        rnd = new byte[32];
                    }

                    MLDSAParameters parameters = (MLDSAParameters)PARAMETERS_MAP.get((String)buf.get("parameterSet"));
                    MLDSAPrivateKeyParameters privParams = new MLDSAPrivateKeyParameters(parameters, sk, null);

                    // sign
                    InternalMLDSASigner signer = new InternalMLDSASigner();

                    signer.init(true, privParams);
                    byte[] sigGenerated;

                    sigGenerated = signer.internalGenerateSignature(message, rnd);
                    assertTrue(Arrays.areEqual(sigGenerated, signature));

                }
                buf.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    public void testSigVerCombinedVectorSet()
        throws IOException
    {
        InputStream src = TestResourceFinder.findTestResource("pqc/crypto/mldsa", "ML-DSA-sigVer.txt");
        BufferedReader bin = new BufferedReader(new InputStreamReader(src));

        String line = null;
        HashMap<String, String> buf = new HashMap<String, String>();
        while ((line = bin.readLine()) != null)
        {
            line = line.trim();

            if (line.startsWith("#"))
            {
                continue;
            }
            if (line.length() == 0)
            {
                if (!buf.isEmpty())
                {
                    boolean expectedResult = TestUtils.parseBoolean((String)buf.get("testPassed"));

                    byte[] pk = Hex.decode((String)buf.get("pk"));
                    byte[] message = Hex.decode((String)buf.get("message"));
                    byte[] signature = Hex.decode((String)buf.get("signature"));

                    MLDSAParameters parameters = (MLDSAParameters)PARAMETERS_MAP.get((String)buf.get("parameterSet"));

                    MLDSAPublicKeyParameters pubParams = new MLDSAPublicKeyParameters(parameters, pk);

                    InternalMLDSASigner verifier = new InternalMLDSASigner();
                    verifier.init(false, pubParams);

                    boolean verifyResult = verifier.internalVerifySignature(message, signature);
                    assertEquals(expectedResult, verifyResult);
                }
                buf.clear();

                continue;
            }

            int a = line.indexOf("=");
            if (a > -1)
            {
                buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
            }
        }
    }

    private class InternalMLDSASigner
        extends MLDSASigner
    {
        public byte[] internalGenerateSignature(byte[] message, byte[] rnd)
        {
            return super.internalGenerateSignature(message, rnd);
        }

        public boolean internalVerifySignature(byte[] message, byte[] signature)
        {
            return super.internalVerifySignature(message, signature);
        }
    }

    public void testComponentLengthChecks()
        throws Exception
    {
        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
        kpGen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters)kp.getPrivate();
        MLDSAPublicKeyParameters pub = (MLDSAPublicKeyParameters)kp.getPublic();

        byte[][] parts = new byte[][]{ priv.getRho(), priv.getK(), priv.getTr(), priv.getS1(), priv.getS2(), priv.getT0(), priv.getT1(), priv.getSeed() };
        String[] names = new String[]{ "rho", "K", "tr", "s1", "s2", "t0", "t1", "seed" };

        // correct lengths are accepted, with and without the optional seed and t1
        new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]);
        new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], null);

        for (int i = 0; i != parts.length; i++)
        {
            for (int delta = -1; delta <= 1; delta += 2)
            {
                byte[][] bad = new byte[parts.length][];
                System.arraycopy(parts, 0, bad, 0, parts.length);
                bad[i] = Arrays.copyOf(parts[i], parts[i].length + delta);
                try
                {
                    new MLDSAPrivateKeyParameters(MLDSAParameters.ml_dsa_44, bad[0], bad[1], bad[2], bad[3], bad[4], bad[5], bad[6], bad[7]);
                    fail("no exception for " + names[i] + " of length " + bad[i].length);
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals("'" + names[i] + "' has invalid length", e.getMessage());
                }
            }
        }

        byte[] rho = pub.getRho();
        byte[] t1 = pub.getT1();

        new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, rho, t1);

        for (int delta = -1; delta <= 1; delta += 2)
        {
            try
            {
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, Arrays.copyOf(rho, rho.length + delta), t1);
                fail("no exception for rho of length " + (rho.length + delta));
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("'rho' has invalid length", e.getMessage());
            }

            byte[] badT1 = Arrays.copyOf(t1, t1.length + delta);
            try
            {
                new MLDSAPublicKeyParameters(MLDSAParameters.ml_dsa_44, rho, badT1);
                fail("no exception for t1 of length " + badT1.length);
            }
            catch (IllegalArgumentException e)
            {
                assertEquals("'t1' has invalid length", e.getMessage());
            }

            // SEQUENCE { OCTET STRING rho, OCTET STRING t1 } public key form via PublicKeyFactory
            SubjectPublicKeyInfo spki = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(pub);
            SubjectPublicKeyInfo badSpki = new SubjectPublicKeyInfo(spki.getAlgorithm(),
                new DERSequence(new ASN1Encodable[]{ new DEROctetString(rho), new DEROctetString(badT1) }));
            try
            {
                PublicKeyFactory.createKey(badSpki);
                fail("no exception for SEQUENCE encoded public key with t1 of length " + badT1.length);
            }
            catch (IllegalArgumentException e)
            {
                // expected
            }
        }
    }

    public void testPrivateKeyEmbeddedPublicKeyConsistency()
        throws Exception
    {
        // an ML-DSA OneAsymmetricKey may carry the public key (RFC 9881 sec. 6), and both its rho and its t1 must match the private key
        int[] formats = new int[]{ MLDSAPrivateKeyParameters.BOTH, MLDSAPrivateKeyParameters.SEED_ONLY,
            MLDSAPrivateKeyParameters.EXPANDED_KEY };

        for (int i = 0; i != PARAMETER_SETS.length; i++)
        {
            MLDSAParameters parameters = PARAMETER_SETS[i];
            MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
            kpGen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), parameters));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
            MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters)kp.getPrivate();
            byte[] pub = ((MLDSAPublicKeyParameters)kp.getPublic()).getEncoded();

            byte[] rhoFlip = Arrays.clone(pub);
            rhoFlip[5] ^= 0x01;
            byte[] t1Flip = Arrays.clone(pub);
            t1Flip[t1Flip.length - 1] ^= 0x01;

            for (int j = 0; j != formats.length; j++)
            {
                PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(priv.getParametersWithFormat(formats[j]));

                MLDSAPrivateKeyParameters key = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(withPublicKey(info, pub));
                assertTrue(Arrays.areEqual(pub, key.getPublicKey()));

                checkPublicKeyMismatch(withPublicKey(info, t1Flip), parameters.getName() + " t1");
                checkPublicKeyMismatch(withPublicKey(info, rhoFlip), parameters.getName() + " rho");
            }

            // the constructor directly, given the expanded key and given the seed
            byte[][] encodings = new byte[][]{ priv.getEncoded(), priv.getSeed() };
            for (int j = 0; j != encodings.length; j++)
            {
                new MLDSAPrivateKeyParameters(parameters, encodings[j], new MLDSAPublicKeyParameters(parameters, pub));
                try
                {
                    new MLDSAPrivateKeyParameters(parameters, encodings[j], new MLDSAPublicKeyParameters(parameters, rhoFlip));
                    fail("no exception for " + parameters.getName() + " public key with a different rho");
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals("passed in public key does not match private values", e.getMessage());
                }
            }
        }
    }

    private static PrivateKeyInfo withPublicKey(PrivateKeyInfo info, byte[] publicKey)
        throws IOException
    {
        return new PrivateKeyInfo(info.getPrivateKeyAlgorithm(), info.parsePrivateKey(), null, publicKey);
    }

    private static void checkPublicKeyMismatch(PrivateKeyInfo info, String label)
        throws IOException
    {
        try
        {
            PrivateKeyFactory.createKey(info);
            fail("no exception for mismatched " + label);
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("passed in public key does not match private values", e.getMessage());
        }
    }

    /**
     * RFC 9881 sec. 6: the privateKey is CHOICE { seed [0] OCTET STRING (SIZE (32)), expandedKey OCTET STRING,
     * both SEQUENCE { seed, expandedKey } } and the tag says which arm is present. Each arm must have its
     * exact length, while the three pre-RFC forms of earlier drafts (the raw seed, the raw expanded key and the
     * seed in an untagged OCTET STRING) are still read.
     */
    public void testPrivateKeyInfoChoiceArms()
        throws Exception
    {
        for (int i = 0; i != PARAMETER_SETS.length; i++)
        {
            MLDSAParameters parameters = PARAMETER_SETS[i];
            MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
            kpGen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), parameters));
            MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters)kpGen.generateKeyPair().getPrivate();
            byte[] seed = priv.getSeed();
            byte[] expanded = priv.getEncoded();
            AlgorithmIdentifier algId = PrivateKeyInfoFactory.createPrivateKeyInfo(priv).getPrivateKeyAlgorithm();
            String name = parameters.getName();

            // the RFC forms
            checkChoiceAccepted(name + " seed", algId, new DERTaggedObject(false, 0, new DEROctetString(seed)), expanded);
            checkChoiceAccepted(name + " expandedKey", algId, new DEROctetString(expanded), expanded);
            checkChoiceAccepted(name + " both", algId, new DERSequence(new ASN1Encodable[]{ new DEROctetString(seed), new DEROctetString(expanded) }), expanded);

            // the pre-RFC forms
            checkRawAccepted(name + " raw seed", algId, seed, expanded);
            checkRawAccepted(name + " raw expandedKey", algId, expanded, expanded);
            checkChoiceAccepted(name + " untagged seed", algId, new DEROctetString(seed), expanded);

            // the seed arm must be exactly 32 bytes
            checkChoiceRejected(name + " tagged expandedKey", algId, new DERTaggedObject(false, 0, new DEROctetString(expanded)), "seed must be 32 bytes");
            checkChoiceRejected(name + " short tagged seed", algId, new DERTaggedObject(false, 0, new DEROctetString(Arrays.copyOf(seed, 31))), "seed must be 32 bytes");
            checkChoiceRejected(name + " long tagged seed", algId, new DERTaggedObject(false, 0, new DEROctetString(Arrays.copyOf(seed, 33))), "seed must be 32 bytes");
            checkChoiceRejected(name + " tag [1]", algId, new DERTaggedObject(false, 1, new DEROctetString(seed)), "unexpected tag");

            // the expandedKey arm must be exactly the expanded key length
            checkChoiceRejected(name + " short expandedKey", algId, new DEROctetString(Arrays.copyOf(expanded, expanded.length - 1)), "invalid length");
            checkChoiceRejected(name + " long expandedKey", algId, new DEROctetString(Arrays.copyOf(expanded, expanded.length + 1)), "invalid length");
            checkChoiceRejected(name + " 31 byte OCTET STRING", algId, new DEROctetString(Arrays.copyOf(seed, 31)), "invalid length");
            checkRawRejected(name + " raw 33 bytes", algId, Arrays.copyOf(seed, 33), "invalid length");

            // both: exactly two elements, a 32 byte seed and an expandedKey of the right length that matches it
            checkChoiceRejected(name + " both with expandedKey as seed", algId, new DERSequence(new ASN1Encodable[]{ new DEROctetString(expanded), new DEROctetString(expanded) }), "seed must be 32 bytes");
            checkChoiceRejected(name + " both with seed as expandedKey", algId, new DERSequence(new ASN1Encodable[]{ new DEROctetString(seed), new DEROctetString(seed) }), "expandedKey must be " + expanded.length + " bytes");
            checkChoiceRejected(name + " both with one element", algId, new DERSequence(new ASN1Encodable[]{ new DEROctetString(seed) }), "both must have 2 elements");
            byte[] flipped = Arrays.clone(expanded);
            flipped[expanded.length - 1] ^= 1;
            checkChoiceRejected(name + " both inconsistent", algId, new DERSequence(new ASN1Encodable[]{ new DEROctetString(seed), new DEROctetString(flipped) }), "inconsistent");
        }
    }

    private static void checkChoiceAccepted(String label, AlgorithmIdentifier algId, ASN1Encodable privateKey, byte[] expanded)
        throws Exception
    {
        MLDSAPrivateKeyParameters key = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(new PrivateKeyInfo(algId, privateKey));
        assertTrue(label, Arrays.areEqual(expanded, key.getEncoded()));
    }

    private static void checkRawAccepted(String label, AlgorithmIdentifier algId, byte[] content, byte[] expanded)
        throws Exception
    {
        MLDSAPrivateKeyParameters key = (MLDSAPrivateKeyParameters)PrivateKeyFactory.createKey(rawPrivateKeyInfo(algId, content));
        assertTrue(label, Arrays.areEqual(expanded, key.getEncoded()));
    }

    private static void checkChoiceRejected(String label, AlgorithmIdentifier algId, ASN1Encodable privateKey, String message)
        throws Exception
    {
        checkRejected(label, new PrivateKeyInfo(algId, privateKey), message);
    }

    private static void checkRawRejected(String label, AlgorithmIdentifier algId, byte[] content, String message)
        throws Exception
    {
        checkRejected(label, rawPrivateKeyInfo(algId, content), message);
    }

    private static void checkRejected(String label, PrivateKeyInfo info, String message)
        throws Exception
    {
        try
        {
            PrivateKeyFactory.createKey(info);
            fail(label + ": accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertTrue(label + ": " + e.getMessage(), e.getMessage().indexOf(message) >= 0);
        }
    }

    // a PrivateKeyInfo whose privateKey OCTET STRING holds the given bytes as its content, not as a DER value
    private static PrivateKeyInfo rawPrivateKeyInfo(AlgorithmIdentifier algId, byte[] content)
    {
        return PrivateKeyInfo.getInstance(new DERSequence(new ASN1Encodable[]{ new ASN1Integer(0), algId, new DEROctetString(content) }));
    }

    public void testExpandedPrivateKeyTrConsistency()
        throws Exception
    {
        // tr is H(pk) (FIPS 204 Algorithm 6), so an expanded key whose tr does not match its rho and t1 must be refused
        for (int i = 0; i != PARAMETER_SETS.length; i++)
        {
            MLDSAParameters parameters = PARAMETER_SETS[i];
            MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
            kpGen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), parameters));
            AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();
            MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters)kp.getPrivate();
            byte[] expanded = priv.getEncoded();

            MLDSAPrivateKeyParameters key = new MLDSAPrivateKeyParameters(parameters, expanded, null);
            assertTrue(Arrays.areEqual(priv.getTr(), key.getTr()));
            assertTrue(Arrays.areEqual(((MLDSAPublicKeyParameters)kp.getPublic()).getEncoded(), key.getPublicKey()));

            // rho (32) || K (32) || tr (64) || ...
            int[] trOffsets = new int[]{ 64, 64 + 63 };
            for (int j = 0; j != trOffsets.length; j++)
            {
                byte[] trFlip = Arrays.clone(expanded);
                trFlip[trOffsets[j]] ^= 0x01;

                try
                {
                    new MLDSAPrivateKeyParameters(parameters, trFlip, null);
                    fail("no exception for " + parameters.getName() + " expanded key with a different tr");
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals("'encoding' has inconsistent tr", e.getMessage());
                }

                PrivateKeyInfo info = PrivateKeyInfoFactory.createPrivateKeyInfo(
                    new MLDSAPrivateKeyParameters(parameters, expanded, null).getParametersWithFormat(MLDSAPrivateKeyParameters.EXPANDED_KEY));
                byte[] infoEnc = info.getEncoded();
                int pos = indexOf(infoEnc, expanded);
                assertTrue(pos > 0);
                infoEnc[pos + trOffsets[j]] ^= 0x01;
                try
                {
                    PrivateKeyFactory.createKey(PrivateKeyInfo.getInstance(infoEnc));
                    fail("no exception for " + parameters.getName() + " PKCS#8 expanded key with a different tr");
                }
                catch (IllegalArgumentException e)
                {
                    assertEquals("'encoding' has inconsistent tr", e.getMessage());
                }
            }
        }
    }

    private static int indexOf(byte[] data, byte[] target)
    {
        for (int i = 0; i <= data.length - target.length; i++)
        {
            if (Arrays.areEqual(data, i, i + target.length, target, 0, target.length))
            {
                return i;
            }
        }
        return -1;
    }

    /*
     * A key from withPreferredFormat() holds its own copy of the key material: destroying it, in the same or another
     * format, must leave the original intact and not destroyed, and a destroyed key cannot be copied.
     */
    public void testPreferredFormatCopyIsIndependent()
    {
        MLDSAKeyPairGenerator kpGen = new MLDSAKeyPairGenerator();
        kpGen.init(new MLDSAKeyGenerationParameters(new SecureRandom(), MLDSAParameters.ml_dsa_44));
        MLDSAPrivateKeyParameters priv = (MLDSAPrivateKeyParameters)kpGen.generateKeyPair().getPrivate();
        byte[] encoding = priv.getEncoded();
        byte[] seed = priv.getSeed();

        int[] formats = { MLDSAPrivateKeyParameters.SEED_ONLY, MLDSAPrivateKeyParameters.EXPANDED_KEY,
            MLDSAPrivateKeyParameters.BOTH, priv.getPreferredFormat() };
        for (int i = 0; i != formats.length; i++)
        {
            MLDSAPrivateKeyParameters copy = priv.withPreferredFormat(formats[i]);
            assertNotSame(priv, copy);
            copy.destroy();

            assertTrue(copy.isDestroyed());
            assertFalse(priv.isDestroyed());
            assertTrue(Arrays.areEqual(encoding, priv.getEncoded()));
            assertTrue(Arrays.areEqual(seed, priv.getSeed()));
        }

        priv.destroy();
        try
        {
            priv.withPreferredFormat(MLDSAPrivateKeyParameters.EXPANDED_KEY);
            fail("destroyed key copied");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }
    }
}
