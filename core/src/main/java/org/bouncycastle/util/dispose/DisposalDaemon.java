package org.bouncycastle.util.dispose;

import org.bouncycastle.util.Properties;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Set;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Frees native allocations once their owning objects are no longer reachable, after running each
 * allocation's dispose action, which clears any key material it holds.
 * <p>
 * The shutdown hook disposes only the allocations whose owners have already been found unreachable.
 * Native state belonging to objects still in use when the JVM exits is not cleared: it may still be
 * in use by another thread, and clearing it under that thread would leave it working with zeroed
 * keys. That memory is returned to the operating system as it is.
 * </p>
 */
public class DisposalDaemon
        implements Runnable
{
    private static final Logger LOG = Logger.getLogger(DisposalDaemon.class.getName());

    private static ReferenceQueue<Disposable> referenceQueue = new ReferenceQueue<Disposable>();

    private static Set<ReferenceWrapperWithDisposerRunnable> refs = ConcurrentHashMap.newKeySet();


    private static final ScheduledExecutorService cleanupExecutor;
    private static final DisposalDaemon disposalDaemon = new DisposalDaemon();
    private static final Thread disposalThread;

    private static final long cleanupDelay;
    private static final String CLEANUP_DELAY_PROP = "org.bouncycastle.native.cleanup_delay";


    static
    {

        cleanupDelay = readCleanupDelay();


        //
        // Clean up executor accepts references that are no longer needed
        // and disposes of them in turn.
        //
        if (cleanupDelay > 0)
        {
            cleanupExecutor = Executors.newSingleThreadScheduledExecutor(new ThreadFactory()
            {
                @Override
                public Thread newThread(Runnable r)
                {
                    Thread t = new Thread(r, "BC Cleanup Executor");
                    t.setDaemon(true);
                    return t;
                }
            });
        }
        else
        {
            cleanupExecutor = null;
        }

        //
        // Sets up the daemon thread that deals with items on the reference
        // queue that may have native code that needs disposing.
        //
        disposalThread = new Thread(disposalDaemon, "BC Disposal Daemon");
        disposalThread.setDaemon(true);
        disposalThread.start();

        addShutdownHook();
    }

    /**
     * Read the cleanup delay, in milliseconds, from CLEANUP_DELAY_PROP: a number of seconds, or of
     * milliseconds with an "ms" suffix. A value that cannot be read is replaced with the default of
     * no delay, and a warning naming the property is logged. Failing instead would fail the
     * initialisation of this class, after which no native object could be created.
     */
    private static long readCleanupDelay()
    {
        String cleanupDelayProp = Properties.getPropertyValue(CLEANUP_DELAY_PROP, "0").trim();
        try
        {
            if (cleanupDelayProp.endsWith("ms"))
            {
                return Math.max(Long.parseLong(cleanupDelayProp.substring(0, cleanupDelayProp.length() - 2).trim()), 0);
            }

            long seconds = Long.parseLong(cleanupDelayProp);
            if (seconds > Long.MAX_VALUE / 1000L)
            {
                throw new NumberFormatException("too large: " + cleanupDelayProp);
            }
            return Math.max(seconds * 1000L, 0);
        }
        catch (NumberFormatException e)
        {
            LOG.warning(CLEANUP_DELAY_PROP + " must be a whole number of seconds, or of milliseconds followed by ms, "
                + "using 0: " + cleanupDelayProp);
            return 0;
        }
    }

    private static void addShutdownHook()
    {
        //
        // On shutdown clean up the reference queue.
        //
        Runtime.getRuntime().addShutdownHook(new Thread()
        {
            @Override
            public void run()
            {
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine("Shutdown hook started");
                }
                ReferenceWrapperWithDisposerRunnable item =
                        (ReferenceWrapperWithDisposerRunnable) referenceQueue.poll();
                while (item != null)
                {
                    refs.remove(item);
                    item.dispose();
                    item = (ReferenceWrapperWithDisposerRunnable) referenceQueue.poll();

                    if (LOG.isLoggable(Level.FINE))
                    {
                        LOG.fine("Shutdown hook disposed: " + item);
                    }
                }

            }
        });
    }

    public static void addDisposable(Disposable disposable)
    {
        ReferenceWrapperWithDisposerRunnable ref = new ReferenceWrapperWithDisposerRunnable(disposable, referenceQueue);
        refs.add(ref);
        if (LOG.isLoggable(Level.FINE))
        {
            LOG.fine("Registered: " + disposable.toString());
        }
    }

    public void run()
    {
        for (; ; )
        {
            try
            {
                final ReferenceWrapperWithDisposerRunnable item =
                        (ReferenceWrapperWithDisposerRunnable) referenceQueue.remove();
                refs.remove(item);


                if (cleanupExecutor == null)
                {
                    if (LOG.isLoggable(Level.FINE))
                    {
                        LOG.fine("Disposed: " + item);
                    }
                    item.dispose();
                }
                else
                {
                    //
                    // Delay in order to avoid freeing a reference that the GC has
                    // decided is unreachable concurrently with its last use.
                    //
                    cleanupExecutor.schedule(new Runnable()
                    {
                        @Override
                        public void run()
                        {
                            if (LOG.isLoggable(Level.FINE))
                            {
                                LOG.fine("Disposed: " + item);
                            }
                            item.dispose();
                        }
                    }, cleanupDelay, TimeUnit.MILLISECONDS);
                }

            }
            catch (InterruptedException iex)
            {
                Thread.currentThread().interrupt();
            }
            catch (Throwable e)
            {
                LOG.warning("exception in disposal thread: " + e.getMessage());
            }
        }
    }

    private static class ReferenceWrapperWithDisposerRunnable
            extends PhantomReference<Disposable>
    {

        private final Runnable disposer;
        private final String label;

        /**
         * Creates a new phantom reference that refers to the given object and
         * is registered with the given queue.
         *
         * <p> It is possible to create a phantom reference with a <tt>null</tt>
         * queue, but such a reference is completely useless: Its <tt>get</tt>
         * method will always return null and, since it does not have a queue, it
         * will never be enqueued.
         *
         * @param referent the object the new phantom reference will refer to
         * @param q        the queue with which the reference is to be registered,
         *                 or <tt>null</tt> if registration is not required
         */
        public ReferenceWrapperWithDisposerRunnable(Disposable referent, ReferenceQueue<? super Disposable> q)
        {
            super(referent, q);
            this.label = referent.toString(); // capture label from referent
            this.disposer = referent.getDisposeAction();
        }

        public void dispose()
        {
            disposer.run();
        }

        public String toString()
        {
            return label;
        }
    }
}

