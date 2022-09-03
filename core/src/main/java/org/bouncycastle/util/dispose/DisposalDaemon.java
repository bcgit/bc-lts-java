package org.bouncycastle.util.dispose;

import java.lang.ref.PhantomReference;
import java.lang.ref.Reference;
import java.lang.ref.ReferenceQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

public class DisposalDaemon
    implements Runnable
{
    private static final Logger LOG = Logger.getLogger(DisposalDaemon.class.getName());

    private static ReferenceQueue<Disposable> referenceQueue = new ReferenceQueue<Disposable>();

    private static final DisposalDaemon disposalDaemon = new DisposalDaemon();
    private static final Thread disposalThread;

    static
    {
        disposalThread = new Thread(disposalDaemon, "BC Disposal Daemon");
        disposalThread.setDaemon(true);
        disposalThread.start();
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
                Reference<? extends Disposable> item = referenceQueue.poll();
                while (item != null)
                {
                    item.get().dispose();
                    item = referenceQueue.poll();
                }
                super.run();
            }
        });
    }

    public static void addDisposable(Disposable disposable)
    {
        // TODO: is this correct?
        new PhantomReference<Disposable>(disposable, referenceQueue);
    }

    /**
     * Sets up the daemon thread that deals with items on the reference
     * queue that may have native code that needs disposing.
     */
    public static void startReferenceQueueThread()
    {
        Thread th = new Thread(new Runnable()
        {
            @Override
            public void run()
            {


            }
        });

        th.setPriority(Thread.MIN_PRIORITY);
        th.setDaemon(true);
        th.start();
    }
    public void run()
    {
        for (;;)
        {
            try
            {
                Reference<? extends Disposable> item = referenceQueue.remove();
                item.get().dispose();
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
}
