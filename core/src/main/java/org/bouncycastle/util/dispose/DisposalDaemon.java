package org.bouncycastle.util.dispose;

import org.bouncycastle.util.Properties;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DisposalDaemon
        implements Runnable
{
    private static final Logger LOG = Logger.getLogger(DisposalDaemon.class.getName());

    private static ReferenceQueue<Disposable> referenceQueue = new ReferenceQueue<Disposable>();

    private static Set<ReferenceWrapperWithDisposerRunnable> refs =
            Collections.synchronizedSet(new HashSet<ReferenceWrapperWithDisposerRunnable>());

    private static AtomicLong ctr = new AtomicLong(Long.MIN_VALUE);

    private static final ScheduledExecutorService cleanupExecutor;
    private static final DisposalDaemon disposalDaemon = new DisposalDaemon();
    private static final Thread disposalThread;

    private static final long cleanupDelay;
    private static final String CLEANUP_DELAY_PROP = "org.bouncycastle.native.cleanup_delay";


    static
    {
        cleanupDelay = Properties.asInteger(CLEANUP_DELAY_PROP, 5);

        //
        // Clean up executor accepts references that are no longer needed
        // and disposes of them in turn.
        //
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

        //
        // Sets up the daemon thread that deals with items on the reference
        // queue that may have native code that needs disposing.
        //
        disposalThread = new Thread(disposalDaemon, "BC Disposal Daemon");
        disposalThread.setDaemon(true);
        disposalThread.start();

        addShutdownHook();
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
                }, cleanupDelay, TimeUnit.SECONDS);


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

