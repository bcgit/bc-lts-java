package org.bouncycastle.util.dispose;

public abstract class NativeReference
    implements Disposable
{
    protected final long reference;
    private boolean disposed = false;


    public NativeReference(long reference)
    {
        this.reference = reference;

        DisposalDaemon.addDisposable(this);
    }


    @Override
    public void dispose()
    {
        if (disposed)
        {
            return;
        }
        destroy(reference);
        disposed = true;
    }

    /**
     * Implement this method to tie in whatever logic is needed
     * to call the native side to clean up / free memory allocated there.
     * @param reference the reference.
     */
    protected abstract void destroy(long reference);


    public boolean isDisposed()
    {
        return disposed;
    }

    public long getReference()
    {
        if (disposed)
        {
            throw new IllegalStateException("native reference has been disposed");
        }
        return reference;
    }
}
