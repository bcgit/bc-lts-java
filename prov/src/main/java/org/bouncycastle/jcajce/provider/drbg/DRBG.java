package org.bouncycastle.jcajce.provider.drbg;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.SecureRandom;
import java.security.SecureRandomSpi;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;
import org.bouncycastle.crypto.prng.SP800SecureRandomBuilder;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.ClassUtil;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Properties;
import org.bouncycastle.util.Strings;

/**
 * <b>DRBG Configuration</b><br/>
 * <p>org.bouncycastle.drbg.gather_pause_secs - is to stop the entropy collection thread from grabbing all
 * available entropy on the system. The original motivation for the hybrid infrastructure was virtual machines
 * sometimes produce very few bits of entropy a second, the original approach (which "worked" at least for BC) was
 * to just read on the second thread and allow things to progress around it, but it did tend to hog the system
 * if other processes were using /dev/random. By default the thread will pause for 5 seconds between 64 bit reads,
 * increasing this time will reduce the demands on the system entropy pool. Ideally the pause will be set to large
 * enough to allow everyone to work together, but small enough to ensure the provider's DRBG is being regularly
 * reseeded.
 * </p>
 * <p>org.bouncycastle.drbg.entropysource - is the class name for an implementation of EntropySourceProvider.
 * For example, one could be provided which just reads directly from /dev/random and the extra infrastructure used here
 * could be avoided.</p>
 */
public class DRBG
{
    private static final String PREFIX = DRBG.class.getName();

    public static class Mappings
        extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("SecureRandom.DEFAULT", PREFIX + "$Default");
            provider.addAlgorithm("SecureRandom.NONCEANDIV", PREFIX + "$NonceAndIV");
        }
    }

    public static class Default
        extends SecureRandomSpi
    {
        private static final SecureRandom random = createBaseRandom(true);

        public Default()
        {
        }

        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        protected byte[] engineGenerateSeed(int numBytes)
        {
            return random.generateSeed(numBytes);
        }
    }

    public static class NonceAndIV
        extends SecureRandomSpi
    {
        private static final SecureRandom random = createBaseRandom(false);

        public NonceAndIV()
        {
        }

        protected void engineSetSeed(byte[] bytes)
        {
            random.setSeed(bytes);
        }

        protected void engineNextBytes(byte[] bytes)
        {
            random.nextBytes(bytes);
        }

        protected byte[] engineGenerateSeed(int numBytes)
        {
            return random.generateSeed(numBytes);
        }
    }

    private static SecureRandom createBaseRandom(boolean isPredictionResistant)
    {
        if (Properties.getPropertyValue("org.bouncycastle.drbg.entropysource") != null)
        {
            EntropySourceProvider entropyProvider = createEntropySource();

            EntropySource initSource = entropyProvider.get(16 * 8);

            byte[] personalisationString = isPredictionResistant
                ? generateDefaultPersonalizationString(initSource.getEntropy())
                : generateNonceIVPersonalizationString(initSource.getEntropy());

            return new SP800SecureRandomBuilder(entropyProvider)
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), initSource.getEntropy(), isPredictionResistant);
        }
        else
        {
            final EntropySourceProvider entropySourceProvider = CryptoServicesRegistrar.getDefaultEntropySourceProvider();
            EntropySource source = entropySourceProvider.get(256);

            byte[] personalisationString = isPredictionResistant
                ? generateDefaultPersonalizationString(source.getEntropy())
                : generateNonceIVPersonalizationString(source.getEntropy());

            return new SP800SecureRandomBuilder(new EntropySourceProvider()
            {
                @Override
                public EntropySource get(int bitsRequired)
                {
                    return entropySourceProvider.get(bitsRequired);
                }
            })
                .setPersonalizationString(personalisationString)
                .buildHash(new SHA512Digest(), source.getEntropy(), isPredictionResistant);
        }
    }

    private static EntropySourceProvider createEntropySource()
    {
        final String sourceClass = Properties.getPropertyValue("org.bouncycastle.drbg.entropysource");

        return AccessController.doPrivileged(new PrivilegedAction<EntropySourceProvider>()
        {
            public EntropySourceProvider run()
            {
                try
                {
                    Class clazz = ClassUtil.loadClass(DRBG.class, sourceClass);

                    return (EntropySourceProvider)clazz.newInstance();
                }
                catch (Exception e)
                {
                    throw new IllegalStateException("entropy source " + sourceClass + " not created: " + e.getMessage(), e);
                }
            }
        });
    }

    private static byte[] generateDefaultPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Default"), seed,
            Pack.longToBigEndian(Thread.currentThread().getId()), Pack.longToBigEndian(System.currentTimeMillis()));
    }

    private static byte[] generateNonceIVPersonalizationString(byte[] seed)
    {
        return Arrays.concatenate(Strings.toByteArray("Nonce"), seed,
            Pack.longToLittleEndian(Thread.currentThread().getId()), Pack.longToLittleEndian(System.currentTimeMillis()));
    }
}
