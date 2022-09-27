package org.bouncycastle.util.dispose;

public abstract class NativeReference
    implements Disposable
{
    protected final long reference;


    public NativeReference(long reference)
    {
        this.reference = reference;
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

}
