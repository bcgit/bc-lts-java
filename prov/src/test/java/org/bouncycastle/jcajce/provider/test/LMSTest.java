package org.bouncycastle.jcajce.provider.test;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidParameterException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.security.auth.Destroyable;

import junit.framework.TestCase;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;
import org.bouncycastle.pqc.jcajce.interfaces.LMSPrivateKey;
import org.bouncycastle.pqc.jcajce.spec.LMSHSSKeyGenParameterSpec;
import org.bouncycastle.pqc.jcajce.spec.LMSKeyGenParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * LMS is now promoted to the BC provider.
 */
public class LMSTest
    extends TestCase
{
    public void setUp()
    {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null)
        {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    public void testKeyPairGenerators()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        KeyPair kp = kpGen.generateKeyPair();

        trySigning(kp);

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        kp = kpGen.generateKeyPair();

        trySigning(kp);

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        kp = kpGen.generateKeyPair();

        trySigning(kp);
    }

    private void trySigning(KeyPair keyPair)
        throws Exception
    {
        byte[] msg = Strings.toByteArray("Hello, world!");
        Signature signer = Signature.getInstance("LMS", "BC");

        signer.initSign(keyPair.getPrivate(), new SecureRandom());

        signer.update(msg);

        byte[] sig = signer.sign();

        signer.initVerify(keyPair.getPublic());

        signer.update(msg);

        assertTrue(signer.verify(sig));
    }

    /**
     * A destroyed LMS private key must stop handing out its secret at the JCA boundary, and the
     * refusal has to be more than a flag: the key can no longer be encoded, sharded or serialized,
     * and signing fails. The non-secret parts stay readable, which is what makes destroy() usable
     * on a key whose index a caller still needs to record.
     */
    public void testDestroyPrivateKey()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", "BC");

        kpg.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
            new SecureRandom());

        KeyPair kp = kpg.generateKeyPair();

        LMSPrivateKey privKey = (LMSPrivateKey)kp.getPrivate();

        // baseline: signs, encodes, and reports itself intact
        byte[] msg = Strings.toByteArray("Hello, world!");

        Signature signer = Signature.getInstance("LMS", "BC");
        signer.initSign(privKey);
        signer.update(msg);
        byte[] sig = signer.sign();

        Signature verifier = Signature.getInstance("LMS", "BC");
        verifier.initVerify(kp.getPublic());
        verifier.update(msg);
        assertTrue(verifier.verify(sig));

        assertNotNull(privKey.getEncoded());
        assertFalse(((Destroyable)privKey).isDestroyed());

        long levels = privKey.getLevels();
        long usagesRemaining = privKey.getUsagesRemaining();
        long index = privKey.getIndex();

        ((Destroyable)privKey).destroy();

        assertTrue(((Destroyable)privKey).isDestroyed());

        try
        {
            privKey.getEncoded();
            fail("getEncoded on a destroyed key");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        try
        {
            privKey.extractKeyShard(1);
            fail("extractKeyShard on a destroyed key");
        }
        catch (IllegalStateException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        // serialization goes through getEncoded, and must surface as an IOException rather than
        // writing a key with no secret in it
        try
        {
            ObjectOutputStream oOut = new ObjectOutputStream(new ByteArrayOutputStream());
            oOut.writeObject(privKey);
            oOut.close();
            fail("serialization of a destroyed key");
        }
        catch (java.io.IOException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        // and it can no longer produce a signature - refused at initSign, as the JCA contract
        // for an unusable key requires, rather than partway through signing
        try
        {
            Signature failed = Signature.getInstance("LMS", "BC");
            failed.initSign(privKey);
            fail("initSign with a destroyed key");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("key destroyed", e.getMessage());
        }

        // the non-secret parts survive, deliberately
        assertEquals(levels, privKey.getLevels());
        assertEquals(usagesRemaining, privKey.getUsagesRemaining());
        assertEquals(index, privKey.getIndex());

        // a destroyed key is only equal to itself
        assertTrue(privKey.equals(privKey));
        assertFalse(privKey.equals(kpg.generateKeyPair().getPrivate()));

        // destroy is idempotent
        ((Destroyable)privKey).destroy();
        assertTrue(((Destroyable)privKey).isDestroyed());
    }

    /**
     * fromNames listed all twenty LM signature parameter sets but only four of the sixteen LM-OTS
     * ones, so every sha256-n24 and shake256 name was refused even though the constant existed and
     * the signature side accepted its counterpart. Every name in the table has to resolve to the
     * constant it is named for, and an unknown name still has to be refused.
     */
    public void testKeyGenParameterSpecFromNames()
        throws Exception
    {
        String[] sigNames = new String[]{ "sha256-n32", "sha256-n24", "shake256-n32", "shake256-n24" };
        String[] heights = new String[]{ "h5", "h10", "h15", "h20", "h25" };
        String[] widths = new String[]{ "w1", "w2", "w4", "w8" };

        for (int i = 0; i != sigNames.length; i++)
        {
            for (int h = 0; h != heights.length; h++)
            {
                for (int w = 0; w != widths.length; w++)
                {
                    String sigName = "lms-" + sigNames[i] + "-" + heights[h];
                    String otsName = sigNames[i] + "-" + widths[w];

                    LMSKeyGenParameterSpec spec = LMSKeyGenParameterSpec.fromNames(sigName, otsName);

                    // the names have to resolve to the parameter sets they name, not merely to
                    // something - a table typo would otherwise pass unnoticed
                    assertEquals(sigName, "lms_" + sigNames[i].replace('-', '_') + "_" + heights[h],
                        lmsigParametersName(spec.getSigParams()));
                    assertEquals(otsName, sigNames[i].replace('-', '_') + "_" + widths[w],
                        lmOtsParametersName(spec.getOtsParams()));
                }
            }
        }

        // and the negative path: an unknown name on either side is still refused
        try
        {
            LMSKeyGenParameterSpec.fromNames("lms-sha256-n32-h7", "sha256-n32-w4");
            fail("unrecognized LM signature parameter name accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("LM signature parameter name lms-sha256-n32-h7 not recognized", e.getMessage());
        }

        try
        {
            LMSKeyGenParameterSpec.fromNames("lms-sha256-n32-h5", "sha256-n32-w3");
            fail("unrecognized LM OTS parameter name accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("LM OTS parameter name sha256-n32-w3 not recognized", e.getMessage());
        }
    }

    private static String lmsigParametersName(LMSigParameters params)
    {
        LMSigParameters[] all = new LMSigParameters[]{
            LMSigParameters.lms_sha256_n32_h5, LMSigParameters.lms_sha256_n32_h10, LMSigParameters.lms_sha256_n32_h15,
            LMSigParameters.lms_sha256_n32_h20, LMSigParameters.lms_sha256_n32_h25,
            LMSigParameters.lms_sha256_n24_h5, LMSigParameters.lms_sha256_n24_h10, LMSigParameters.lms_sha256_n24_h15,
            LMSigParameters.lms_sha256_n24_h20, LMSigParameters.lms_sha256_n24_h25,
            LMSigParameters.lms_shake256_n32_h5, LMSigParameters.lms_shake256_n32_h10, LMSigParameters.lms_shake256_n32_h15,
            LMSigParameters.lms_shake256_n32_h20, LMSigParameters.lms_shake256_n32_h25,
            LMSigParameters.lms_shake256_n24_h5, LMSigParameters.lms_shake256_n24_h10, LMSigParameters.lms_shake256_n24_h15,
            LMSigParameters.lms_shake256_n24_h20, LMSigParameters.lms_shake256_n24_h25 };
        String[] names = new String[]{
            "lms_sha256_n32_h5", "lms_sha256_n32_h10", "lms_sha256_n32_h15", "lms_sha256_n32_h20", "lms_sha256_n32_h25",
            "lms_sha256_n24_h5", "lms_sha256_n24_h10", "lms_sha256_n24_h15", "lms_sha256_n24_h20", "lms_sha256_n24_h25",
            "lms_shake256_n32_h5", "lms_shake256_n32_h10", "lms_shake256_n32_h15", "lms_shake256_n32_h20", "lms_shake256_n32_h25",
            "lms_shake256_n24_h5", "lms_shake256_n24_h10", "lms_shake256_n24_h15", "lms_shake256_n24_h20", "lms_shake256_n24_h25" };

        for (int i = 0; i != all.length; i++)
        {
            if (all[i] == params)
            {
                return names[i];
            }
        }
        return "unknown";
    }

    private static String lmOtsParametersName(LMOtsParameters params)
    {
        LMOtsParameters[] all = new LMOtsParameters[]{
            LMOtsParameters.sha256_n32_w1, LMOtsParameters.sha256_n32_w2, LMOtsParameters.sha256_n32_w4, LMOtsParameters.sha256_n32_w8,
            LMOtsParameters.sha256_n24_w1, LMOtsParameters.sha256_n24_w2, LMOtsParameters.sha256_n24_w4, LMOtsParameters.sha256_n24_w8,
            LMOtsParameters.shake256_n32_w1, LMOtsParameters.shake256_n32_w2, LMOtsParameters.shake256_n32_w4, LMOtsParameters.shake256_n32_w8,
            LMOtsParameters.shake256_n24_w1, LMOtsParameters.shake256_n24_w2, LMOtsParameters.shake256_n24_w4, LMOtsParameters.shake256_n24_w8 };
        String[] names = new String[]{
            "sha256_n32_w1", "sha256_n32_w2", "sha256_n32_w4", "sha256_n32_w8",
            "sha256_n24_w1", "sha256_n24_w2", "sha256_n24_w4", "sha256_n24_w8",
            "shake256_n32_w1", "shake256_n32_w2", "shake256_n32_w4", "shake256_n32_w8",
            "shake256_n24_w1", "shake256_n24_w2", "shake256_n24_w4", "shake256_n24_w8" };

        for (int i = 0; i != all.length; i++)
        {
            if (all[i] == params)
            {
                return names[i];
            }
        }
        return "unknown";
    }

    /**
     * KeyPairGenerator.initialize(int, SecureRandom) is specified to throw InvalidParameterException
     * where the strength makes no sense, which LMS cannot use at all. It extends
     * IllegalArgumentException, so code catching the old type still matches.
     */
    public void testKeyPairGeneratorStrengthRejected()
        throws Exception
    {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("LMS", "BC");

        try
        {
            kpg.initialize(2048, new SecureRandom());
            fail("initialize(int, SecureRandom) accepted");
        }
        catch (InvalidParameterException e)
        {
            assertEquals("use AlgorithmParameterSpec", e.getMessage());
        }

        // the pre-existing contract still holds for a caller catching the supertype
        try
        {
            kpg.initialize(2048, new SecureRandom());
            fail("initialize(int, SecureRandom) accepted");
        }
        catch (IllegalArgumentException e)
        {
            assertEquals("use AlgorithmParameterSpec", e.getMessage());
        }
    }

    public void testKeyFactoryLMSKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());

        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), "BC");

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    public void testPublicKeyEncodingLength()
        throws Exception
    {
        KeyPairGenerator kpGen1 = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen1.initialize(new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1));

        KeyPair kp1 = kpGen1.generateKeyPair();

        KeyPairGenerator kpGen2 = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen2.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        KeyPair kp2 = kpGen2.generateKeyPair();

        assertEquals(kp1.getPublic().getEncoded().length, kp2.getPublic().getEncoded().length);
    }

    public void testKeyFactoryHSSKey()
        throws Exception
    {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w1)
            ), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(kp.getPublic().getEncoded());

        KeyFactory kFact = KeyFactory.getInstance("LMS", "BC");

        PublicKey pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);

        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded());
        
        PrivateKey priv1 = kFact.generatePrivate(pkcs8KeySpec);

        assertEquals(kp.getPrivate(), priv1);

        kFact = KeyFactory.getInstance(PKCSObjectIdentifiers.id_alg_hss_lms_hashsig.getId(), "BC");

        pub1 = kFact.generatePublic(x509KeySpec);

        assertEquals(kp.getPublic(), pub1);
    }

    public void testKeyGenAndSignTwoSigsWithShardHSS()
        throws Exception
    {
        byte[] msg1 = Strings.toByteArray("Hello, world!");
        byte[] msg2 = Strings.toByteArray("Now is the time");

        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("LMS", "BC");

        kpGen.initialize(
            new LMSHSSKeyGenParameterSpec(
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4),
                new LMSKeyGenParameterSpec(LMSigParameters.lms_sha256_n32_h5, LMOtsParameters.sha256_n32_w4)), new SecureRandom());

        KeyPair kp = kpGen.generateKeyPair();

        LMSPrivateKey privKey = ((LMSPrivateKey)kp.getPrivate()).extractKeyShard(2);

        assertEquals(2,  ((LMSPrivateKey)kp.getPrivate()).getIndex());

        assertEquals(2, privKey.getUsagesRemaining());
        assertEquals(0, privKey.getIndex());

        Signature signer = Signature.getInstance("LMS", "BC");

        signer.initSign(privKey);

        signer.update(msg1);

        byte[] sig1 = signer.sign();

        assertEquals(1, privKey.getIndex());

        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig1));

        signer.initSign(privKey);

        signer.update(msg2);

        byte[] sig2 = signer.sign();

        assertEquals(0, privKey.getUsagesRemaining());

        try
        {
            signer.update(msg2);

            fail("no exception");
        }
        catch (SignatureException e)
        {
            assertEquals("hss private key shard is exhausted", e.getMessage());
        }

        signer = Signature.getInstance("LMS", "BC");

        signer.initVerify(kp.getPublic());

        signer.update(msg2);

        assertTrue(signer.verify(sig2));
  
        try
        {
            signer.initSign(privKey);
            fail("no exception");
        }
        catch (InvalidKeyException e)
        {
            assertEquals("private key exhausted", e.getMessage());
        }

        assertEquals(2,  ((LMSPrivateKey)kp.getPrivate()).getIndex());

        signer.initSign(kp.getPrivate());

        signer.update(msg1);

        byte[] sig = signer.sign();
        
        signer.initVerify(kp.getPublic());

        signer.update(msg1);

        assertTrue(signer.verify(sig));
        assertFalse(Arrays.areEqual(sig1, sig));
        assertEquals(3,  ((LMSPrivateKey)kp.getPrivate()).getIndex());
    }
}
