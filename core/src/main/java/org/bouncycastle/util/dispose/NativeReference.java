package org.bouncycastle.util.dispose;

public abstract class NativeReference
    implements Disposable
{
    protected final long reference;

    private boolean actionRead = false;


    public NativeReference(long reference)
    {
        this.reference = reference;
        DisposalDaemon.addDisposable(this);
    }


    public final Runnable getDisposeAction()
    {
        if (actionRead)
        {
            return null;
        }
        actionRead = true;
        return createAction();
    }

    protected abstract Runnable createAction();

    public boolean isActionRead()
    {
        return actionRead;
    }


    public long getReference()
    {
        return reference;
    }

}
