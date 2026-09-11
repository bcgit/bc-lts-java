package org.bouncycastle.jcajce.provider.asymmetric.dsa;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.util.Enumeration;

import javax.security.auth.Destroyable;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DSAParameter;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.KeyUtil;
import org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrivateKeyHashUtil;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

public class BCDSAPrivateKey
    implements DSAPrivateKey, Destroyable, PKCS12BagAttributeCarrier
{
    private static final long serialVersionUID = -4677259546958385734L;

    private BigInteger          x;
    private transient DSAParams dsaSpec;

    private transient PKCS12BagAttributeCarrierImpl attrCarrier = new PKCS12BagAttributeCarrierImpl();

    private transient volatile boolean destroyed;
    private transient int destroyedHashCode;

    protected BCDSAPrivateKey()
    {
    }

    BCDSAPrivateKey(
        DSAPrivateKey key)
    {
        this.x = key.getX();
        this.dsaSpec = key.getParams();
    }

    BCDSAPrivateKey(
        DSAPrivateKeySpec spec)
    {
        this.x = spec.getX();
        this.dsaSpec = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
    }

    public BCDSAPrivateKey(
        PrivateKeyInfo info)
        throws IOException
    {
        DSAParameter    params = DSAParameter.getInstance(info.getPrivateKeyAlgorithm().getParameters());
        ASN1Integer      derX = (ASN1Integer)info.parsePrivateKey();

        this.x = derX.getValue();
        this.dsaSpec = new DSAParameterSpec(params.getP(), params.getQ(), params.getG());
    }

    BCDSAPrivateKey(
        DSAPrivateKeyParameters params)
    {
        this.x = params.getX();
        this.dsaSpec = new DSAParameterSpec(params.getParameters().getP(), params.getParameters().getQ(), params.getParameters().getG());
    }

    public String getAlgorithm()
    {
        return "DSA";
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

        return KeyUtil.getEncodedPrivateKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.id_dsa, new DSAParameter(dsaSpec.getP(), dsaSpec.getQ(), dsaSpec.getG()).toASN1Primitive()), new ASN1Integer(getX()));
    }

    public DSAParams getParams()
    {
        return dsaSpec;
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

        if (!(o instanceof DSAPrivateKey))
        {
            return false;
        }

        DSAPrivateKey other = (DSAPrivateKey)o;

        // a destroyed key no longer exposes its value, so it is only equal to itself.
        if (isDestroyed() || ((o instanceof Destroyable) && ((Destroyable)o).isDestroyed()))
        {
            return false;
        }

        int len = Math.max(
            (getParams().getQ().bitLength() + 7) / 8,
            (other.getParams().getQ().bitLength() + 7) / 8);

        return this.getParams().getG().equals(other.getParams().getG())
            && this.getParams().getP().equals(other.getParams().getP())
            && this.getParams().getQ().equals(other.getParams().getQ())
            && BigIntegers.areSecretValuesEqual(len, this.getX(), other.getX());
    }

    public synchronized int hashCode()
    {
        BigInteger value = x;

        if (value == null)
        {
            return destroyedHashCode;
        }

        return PrivateKeyHashUtil.dsaHashCode(getParams(), value);
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

    private void readObject(
        ObjectInputStream in)
        throws IOException, ClassNotFoundException
    {
        in.defaultReadObject();

        this.dsaSpec = new DSAParameterSpec((BigInteger)in.readObject(), (BigInteger)in.readObject(), (BigInteger)in.readObject());
        this.attrCarrier = new PKCS12BagAttributeCarrierImpl();
    }

    private synchronized void writeObject(
        ObjectOutputStream out)
        throws IOException
    {
        // the private value is serialized directly by defaultWriteObject, so a destroyed key
        // cannot be written; IOException, not IllegalStateException, as declared by the contract.
        if (destroyed)
        {
            throw new IOException("key destroyed");
        }

        out.defaultWriteObject();

        out.writeObject(dsaSpec.getP());
        out.writeObject(dsaSpec.getQ());
        out.writeObject(dsaSpec.getG());
    }

    public String toString()
    {
        StringBuilder   buf = new StringBuilder();
        String          nl = Strings.lineSeparator();

        BigInteger value = x;

        if (value == null)
        {
            return "DSA Private Key [DESTROYED]" + nl;
        }

        BigInteger y = getParams().getG().modPow(value, getParams().getP());

        buf.append("DSA Private Key [").append(DSAUtil.generateKeyFingerprint(y, getParams())).append("]").append(nl);
        buf.append("            Y: ").append(y.toString(16)).append(nl);

        return buf.toString();
    }
}
