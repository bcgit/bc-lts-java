package org.bouncycastle.util.dispose;

import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DisposalDaemon
    implements Runnable
{
    private static final Logger LOG = Logger.getLogger(DisposalDaemon.class.getName());

    private static ReferenceQueue<Disposable> referenceQueue = new ReferenceQueue<Disposable>();

    private static Set<ReferenceWrapperWithDisposerRunnable> refs = Collections.synchronizedSet(new HashSet<ReferenceWrapperWithDisposerRunnable>());

    private static AtomicLong ctr = new AtomicLong(Long.MIN_VALUE);

    private static final DisposalDaemon disposalDaemon = new DisposalDaemon();
    private static final Thread disposalThread;

    static
    {
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
                ReferenceWrapperWithDisposerRunnable item = (ReferenceWrapperWithDisposerRunnable)referenceQueue.poll();
                while (item != null)
                {
                    refs.remove(item);
                    item.dispose();
                    item = (ReferenceWrapperWithDisposerRunnable)referenceQueue.poll();
                }

            }
        });
    }

    public static void addDisposable(Disposable disposable)
    {
        ReferenceWrapperWithDisposerRunnable ref = new ReferenceWrapperWithDisposerRunnable(disposable, referenceQueue);
        refs.add(ref);
    }

    public void run()
    {
        for (; ; )
        {
            try
            {
                ReferenceWrapperWithDisposerRunnable item = (ReferenceWrapperWithDisposerRunnable)referenceQueue.remove();
                refs.remove(item);
                item.dispose();
            }
            catch (InterruptedException iex)
            {
                Thread.currentThread().interrupt();
            }
            catch (Throwable e)
            {
                if (LOG.isLoggable(Level.FINE))
                {
                    LOG.fine("exception in disposal thread: " + e.getMessage());
                }
            }
        }
    }

    private static class ReferenceWrapperWithDisposerRunnable
        extends PhantomReference<Disposable>
//        implements Comparable<ReferenceWrapperWithDisposerRunnable>
    {

        private final long id;
        private final Runnable disposer;

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
            this.disposer = referent.getDisposeAction();
            this.id = ctr.getAndIncrement();
        }

        public void dispose()
        {
            disposer.run();
        }

//        @Override
//        public int compareTo(ReferenceWrapperWithDisposerRunnable o)
//        {
//            return Long.valueOf(o.id).compareTo(id);
//        }
    }
}

