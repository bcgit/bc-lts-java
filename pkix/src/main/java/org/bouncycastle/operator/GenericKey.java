package org.bouncycastle.operator;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public class GenericKey
{
    private AlgorithmIdentifier algorithmIdentifier;
    private Object representation;

    public GenericKey(AlgorithmIdentifier algorithmIdentifier, byte[] representation)
    {
        this.algorithmIdentifier = algorithmIdentifier;
        this.representation = representation;
    }

    protected GenericKey(AlgorithmIdentifier algorithmIdentifier, Object representation)
    {
        this.algorithmIdentifier = algorithmIdentifier;
        this.representation = representation;
    }

    public AlgorithmIdentifier getAlgorithmIdentifier()
    {
        return algorithmIdentifier;
    }

    public Object getRepresentation()
    {
        return representation;
    }
}
