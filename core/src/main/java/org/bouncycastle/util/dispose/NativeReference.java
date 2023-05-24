package org.bouncycastle.util.dispose;

public abstract class NativeReference
        implements Disposable
{
    protected final long reference;
    protected final String label;


    public NativeReference(long reference, String name)
    {
        this.reference = reference;
        this.label = "Reference(" + name + ") 0x" + Long.toHexString(reference);
        DisposalDaemon.addDisposable(this);
    }


    public final Runnable getDisposeAction()
    {
        return createAction();
    }

    protected abstract Runnable createAction();


    public long getReference()
    {
        return reference;
    }

    public String toString()
    {
        return label;
    }
}
