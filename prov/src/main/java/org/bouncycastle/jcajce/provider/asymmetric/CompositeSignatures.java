package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeIndex;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

/**
 * Composite ML-DSA signatures, as specified by draft-ietf-lamps-pq-composite-sigs. One service is
 * registered per combination on the IANA arc 1.3.6.1.5.5.7.6.37-54, plus a "-PREHASH" flavour of each
 * that takes PH(M) from the caller rather than computing it, and the generic "COMPOSITE" service that
 * learns the combination from the key. See {@link CompositeIndex} for the supported combinations.
 */
public class CompositeSignatures
{
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric" + ".compositesignatures.";

    private static final Map<String, String> compositesAttributes = new HashMap<String, String>();

    static
    {
        compositesAttributes.put("SupportedKeyClasses", "org.bouncycastle.jcajce.CompositePublicKey|org.bouncycastle.jcajce.CompositePrivateKey");
        compositesAttributes.put("SupportedKeyFormats", "PKCS#8|X.509");
    }

    public static class Mappings
            extends AsymmetricAlgorithmProvider
    {
        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {
            provider.addAlgorithm("Signature.COMPOSITE", PREFIX + "SignatureSpi$COMPOSITE", compositesAttributes);

            for (ASN1ObjectIdentifier oid : CompositeIndex.getSupportedIdentifiers())
            {
                String algorithmName = CompositeIndex.getAlgorithmName(oid);
                String className = algorithmName.replace('-', '_');

                provider.addAlgorithm("Alg.Alias.KeyFactory", oid, "COMPOSITE");
                provider.addAlgorithm("Alg.Alias.KeyFactory." + algorithmName, "COMPOSITE");
                
                provider.addAlgorithm("KeyPairGenerator." + algorithmName, PREFIX + "KeyPairGeneratorSpi$" + className);
                provider.addAlgorithm("Alg.Alias.KeyPairGenerator", oid, algorithmName);

                provider.addAlgorithm("Signature." + algorithmName, PREFIX + "SignatureSpi$" + className, compositesAttributes);
                provider.addAlgorithm("Alg.Alias.Signature", oid, algorithmName);

                // add pre-hash versions
                provider.addAlgorithm("Signature." + algorithmName + "-PREHASH", PREFIX + "SignatureSpi$" + className + "_PREHASH", compositesAttributes);

                provider.addKeyInfoConverter(oid, new KeyFactorySpi());
            }
        }
    }
}
