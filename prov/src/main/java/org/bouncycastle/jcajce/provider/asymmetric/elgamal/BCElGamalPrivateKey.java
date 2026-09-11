package org.bouncycastle.jcajce.provider.asymmetric.elgamal;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;

import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.params.ElGamalPrivateKeyParameters;
import org.bouncycastle.internal.asn1.oiw.ElGamalParameter;
import org.bouncycastle.internal.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrivateKeyHashUtil;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.bouncycastle.jce.spec.ElGamalPrivateKeySpec;
import org.bouncycastle.util.BigIntegers;

public class BCElGamalPrivateKey
    implements ElGamalPrivateKey, DHPrivateKey, Destroyable, PKCS12BagAttributeCarrier
{
    static final long serialVersionUID = 4819350091141529678L;
        
    private BigInteger      x;

    private transient ElGamalParameterSpec   elSpec;
    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    private transient volatile boolean destroyed;
    private transient int destroyedHashCode;

    protected BCElGamalPrivateKey()
    {
    }

    BCElGamalPrivateKey(
        ElGamalPrivateKey key)
    {
        this.x = key.getX();
        this.elSpec = key.getParameters();
    }

    BCElGamalPrivateKey(
        DHPrivateKey key)
    {
        this.x = key.getX();
        this.elSpec = new ElGamalParameterSpec(key.getParams().getP(), key.getParams().getG());
    }
    
    BCElGamalPrivateKey(
        ElGamalPrivateKeySpec spec)
    {
        this.x = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getParams().getP(), spec.getParams().getG());
    }

    BCElGamalPrivateKey(
        DHPrivateKeySpec spec)
    {
        this.x = spec.getX();
        this.elSpec = new ElGamalParameterSpec(spec.getP(), spec.getG());
    }
    
    BCElGamalPrivateKey(
        PrivateKeyInfo info)
        throws IOException
    {
        ElGamalParameter     params = ElGamalParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        ASN1Integer      derX = ASN1Integer.getInstance(info.parsePrivateKey());

        this.x = derX.getValue();
        this.elSpec = new ElGamalParameterSpec(params.getP(), params.getG());
    }

    BCElGamalPrivateKey(
        ElGamalPrivateKeyParameters params)
    {
        this.x = params.getX();
        this.elSpec = new ElGamalParameterSpec(params.getParameters().getP(), params.getParameters().getG());
    }

    public String getAlgorithm()
    {
        return "ElGamal";
    }

    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat()
    {
        return "PKCS#8";
    }

    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded()
    {
        if (destroyed)
        {
            throw new IllegalStateException("key destroyed");
        }

        try
        {
            PrivateKeyInfo          info = new PrivateKeyInfo(new AlgorithmIdentifier(OIWObjectIdentifiers.elGamalAlgorithm, new ElGamalParameter(elSpec.getP(), elSpec.getG())), new ASN1Integer(getX()));

            return info.getEncoded(ASN1Encoding.DER);
        }
        catch (IOException e)
        {
            return null;
        }
    }

    public ElGamalParameterSpec getParameters()
    {
        return elSpec;
    }

    public DHParameterSpec getParams()
    {
        return new DHParameterSpec(elSpec.getP(), elSpec.getG());
    }
    
    public BigInteger getX()
    {
        BigInteger value = x;

        // the null check catches a destroy() in progress whose flag write is not yet visible;
        // as BigInteger is immutable a non-null snapshot is always the intact pre-destroy value.
        if (destroyed || value == null)
        {
            throw new IllegalStateException("key destroyed");
        }

        return value;
    }

    public boolean equals(
        Object o)
    {
        if (o == this)
        {
            return true;
        }

        if (!(o instanceof DHPrivateKey))
        {
            return false;
        }

        DHPrivateKey other = (DHPrivateKey)o;

        // a destroyed key no longer exposes its value, so it is only equal to itself.
        if (isDestroyed() || ((o instanceof Destroyable) && ((Destroyable)o).isDestroyed()))
        {
            return false;
        }

        int len = Math.max(dhPrivateKeyByteLength(getParams()), dhPrivateKeyByteLength(other.getParams()));

        return this.getParams().getG().equals(other.getParams().getG())
            && this.getParams().getP().equals(other.getParams().getP())
            && this.getParams().getL() == other.getParams().getL()
            && BigIntegers.areSecretValuesEqual(len, this.getX(), other.getX());
    }

    public synchronized int hashCode()
    {
        BigInteger value = x;

        if (value == null)
        {
            return destroyedHashCode;
        }

        return PrivateKeyHashUtil.elGamalHashCode(getParameters(), value);
    }

    /**
     * Destroy this key, clearing the key material it holds.
     * <p>
     * The private value is held as a {@link BigInteger}, which is immutable and so cannot be
     * zeroized in place - destruction drops the internal reference so the value becomes
     * unreachable (cleared on garbage collection). The (public) domain parameters are
     * retained. After destruction {@link #isDestroyed()} returns true, the secret-bearing
     * accessors ({@link #getEncoded()} and {@link #getX()}) throw {@link IllegalStateException}, the key can no longer be
     * serialized, and it is equal only to itself; {@link #hashCode()} retains its
     * pre-destruction value.
     */
    public synchronized void destroy()
    {
        if (!destroyed)
        {
            // freeze the hash before the private value is dropped, so hash containers holding
            // this key keep working.
            try
            {
                this.destroyedHashCode = hashCode();
            }
            catch (RuntimeException e)
            {
                this.destroyedHashCode = -1;
            }

            this.destroyed = true;
            this.x = null;
        }
    }

    public boolean isDestroyed()
    {
        return destroyed;
    }

    private void readObject(
        ObjectInputStream   in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        this.elSpec = new ElGamalParameterSpec((BigInteger)in.readObject(), (BigInteger)in.readObject());
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private synchronized void writeObject(
        ObjectOutputStream  out)
        throws IOException
    {
        // the private value is serialized directly by defaultWriteObject, so a destroyed key
        // cannot be written; IOException, not IllegalStateException, as declared by the contract.
        if (destroyed)
        {
            throw new IOException("key destroyed");
        }

        out.defaultWriteObject();

        out.writeObject(elSpec.getP());
        out.writeObject(elSpec.getG());
    }

    public void setBagAttribute(
        ASN1ObjectIdentifier oid,
        ASN1Encodable attribute)
    {
        attrCarrier.setBagAttribute(oid, attribute);
    }

    public ASN1Encodable getBagAttribute(
        ASN1ObjectIdentifier oid)
    {
        return attrCarrier.getBagAttribute(oid);
    }

    public Enumeration getBagAttributeKeys()
    {
        return attrCarrier.getBagAttributeKeys();
    }

    public boolean hasFriendlyName()
    {
        return attrCarrier.hasFriendlyName();
    }

    public void setFriendlyName(String friendlyName)
    {
        attrCarrier.setFriendlyName(friendlyName);
    }

    private static int dhPrivateKeyByteLength(DHParameterSpec params)
    {
        int l = params.getL();
        if (l > 0)
        {
            return (l + 7) / 8;
        }

        return (params.getP().bitLength() + 7) / 8;
    }
}
