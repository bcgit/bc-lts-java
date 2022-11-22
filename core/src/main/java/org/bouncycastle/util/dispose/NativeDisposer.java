package org.bouncycastle.util.dispose;


public abstract class NativeDisposer
    implements Runnable
{
    private final long reference;
    private boolean called = false;

    public NativeDisposer(long reference)
    {
        this.reference = reference;
    }


    @Override
    public void run()
    {
        if (called)
        {
            return;
        }
        called = true;

        dispose(reference);
    }

    protected abstract void dispose(long reference);

}
