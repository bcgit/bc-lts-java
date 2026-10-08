package org.bouncycastle.util.dispose;

import java.util.logging.Logger;

public abstract class NativeReference
        implements Disposable
{
    private static final Logger LOG = Logger.getLogger(NativeReference.class.getName());

    protected final long reference;
    protected final String label;
    private final Runnable disposeAction;


    public NativeReference(long reference, String name)
    {
        this(reference, name, null);
    }

    /**
     * Base constructor for a reference whose dispose action needs state held by the subclass, such as
     * key material to clear.
     * <p>
     * The dispose action is captured when the reference is registered for disposal, which happens in this
     * constructor - before any field of the subclass has been assigned. A createAction() that reads subclass
     * fields therefore only ever sees their default values, so such state must be passed in here instead.
     * </p>
     *
     * @param reference the native reference.
     * @param name a label for the reference.
     * @param disposeAction the action to run once this reference is no longer reachable.
     */
    protected NativeReference(long reference, String name, Runnable disposeAction)
    {
        this.reference = reference;
        this.label = "Reference(" + name + ") 0x" + Long.toHexString(reference);
        this.disposeAction = disposeAction;
        DisposalDaemon.addDisposable(this);
    }


    public final Runnable getDisposeAction()
    {
        Runnable action = createAction();
        if (action == null)
        {
            // This is called from the constructor, after the native allocation has been made, so
            // failing here would strand it. Report the missing action when disposal comes due.
            final String name = label;
            return new Runnable()
            {
                public void run()
                {
                    LOG.warning("no dispose action for " + name + ", native allocation not released");
                }
            };
        }
        return action;
    }

    /**
     * Return the action to run on disposal. Note: this is called from the NativeReference constructor, so an
     * override must not depend on fields of the subclass. The default returns the action passed to the
     * constructor.
     *
     * @return the dispose action.
     */
    protected Runnable createAction()
    {
        return disposeAction;
    }


    public long getReference()
    {
        return reference;
    }

    public String toString()
    {
        return label;
    }
}
