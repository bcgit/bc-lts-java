package org.bouncycastle.crypto.util;

import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.SHA512tDigest;
import org.bouncycastle.crypto.digests.SHAKEDigest;

/**
 * Basic factory class for message digests.
 */
public final class DigestFactory
{
    private static final Map cloneMap = new HashMap();

    private static interface Cloner
    {
        Digest createClone(Digest original);
    }

    static
    {
        cloneMap.put(createMD5().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return new MD5Digest((MD5Digest)original);
            }
        });
        cloneMap.put(createSHA1().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return new SHA1Digest((SHA1Digest)original);
            }
        });
        cloneMap.put(createSHA224().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return  SHA224Digest.newInstance(original);
            }
        });
        cloneMap.put(createSHA256().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return SHA256Digest.newInstance(original);
            }
        });
        cloneMap.put(createSHA384().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return SHA384Digest.newInstance(original);
            }
        });
        cloneMap.put(createSHA512().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return SHA512Digest.newInstance(original);
            }
        });
        cloneMap.put(createSHA3_224().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return SHA3Digest.newInstance(original);
            }
        });
        cloneMap.put(createSHA3_256().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return SHA3Digest.newInstance(original);
            }
        });
        cloneMap.put(createSHA3_384().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return  SHA3Digest.newInstance(original);
            }
        });
        cloneMap.put(createSHA3_512().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return  SHA3Digest.newInstance(original);
            }
        });

        cloneMap.put(createSHAKE128().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return SHA3Digest.newInstance(original);
            }
        });

        cloneMap.put(createSHAKE256().getAlgorithmName(), new Cloner()
        {
            public Digest createClone(Digest original)
            {
                return SHA3Digest.newInstance(original);
            }
        });
    }

    public static Digest createMD5()
    {
        return new MD5Digest();
    }

    public static Digest createMD5PRF()
    {
        return new MD5Digest();
    }

    public static Digest createSHA1()
    {
        return new SHA1Digest();
    }

    public static Digest createSHA1PRF()
    {
        return new SHA1Digest(CryptoServicePurpose.PRF);
    }

    public static Digest createSHA224()
    {
        return  SHA224Digest.newInstance();
    }

    public static Digest createSHA224PRF()
    {
        return SHA224Digest.newInstance(CryptoServicePurpose.PRF);
    }

    public static Digest createSHA256()
    {
        return SHA256Digest.newInstance();
    }

    public static Digest createSHA256PRF()
    {
        return new SHA256Digest(CryptoServicePurpose.PRF);
    }

    public static Digest createSHA384()
    {
        return SHA384Digest.newInstance();
    }

    public static Digest createSHA384PRF()
    {
        return SHA384Digest.newInstance(CryptoServicePurpose.PRF);
    }

    public static Digest createSHA512()
    {
        return SHA512Digest.newInstance();
    }

    public static Digest createSHA512PRF()
    {
        return SHA512Digest.newInstance(CryptoServicePurpose.PRF);
    }

    public static Digest createSHA512_224()
    {
        return new SHA512tDigest(224);
    }

    public static Digest createSHA512_224PRF()
    {
        return new SHA512tDigest(224, CryptoServicePurpose.PRF);
    }

    public static Digest createSHA512_256()
    {
        return new SHA512tDigest(256);
    }

    public static Digest createSHA512_256PRF()
    {
        return new SHA512tDigest(256, CryptoServicePurpose.PRF);
    }

    public static Digest createSHA3_224()
    {
        return SHA3Digest.newInstance(224);
    }

    public static Digest createSHA3_224PRF()
     {
         return SHA3Digest.newInstance(224, CryptoServicePurpose.PRF);
     }

    public static Digest createSHA3_256()
    {
        return SHA3Digest.newInstance(256);
    }

    public static Digest createSHA3_256PRF()
    {
        return SHA3Digest.newInstance(256, CryptoServicePurpose.PRF);
    }

    public static Digest createSHA3_384()
    {
        return SHA3Digest.newInstance(384);
    }

    public static Digest createSHA3_384PRF()
    {
        return SHA3Digest.newInstance(384, CryptoServicePurpose.PRF);
    }

    public static Digest createSHA3_512()
    {
        return SHA3Digest.newInstance(512);
    }

    public static Digest createSHA3_512PRF()
    {
        return SHA3Digest.newInstance(512, CryptoServicePurpose.PRF);
    }

    public static Digest createSHAKE128()
    {
        return SHAKEDigest.newInstance(128);
    }

    public static Digest createSHAKE256()
    {
        return SHAKEDigest.newInstance(256);
    }

    public static Digest cloneDigest(Digest hashAlg)
    {
        return ((Cloner)cloneMap.get(hashAlg.getAlgorithmName())).createClone(hashAlg);
    }
}
