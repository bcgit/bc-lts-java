package org.bouncycastle.tls.test;

import java.io.IOException;
import java.util.Random;

import org.bouncycastle.tls.DatagramTransport;

public class UnreliableDatagramTransport
    implements DatagramTransport
{

    private final DatagramTransport transport;
    private final Random random;
    private final int maxDroppedReceiving, maxDroppedSending;
    private volatile int percentPacketLossReceiving, percentPacketLossSending;
    private int droppedReceiving = 0, droppedSending = 0;

    /**
     * Lose the given percentages of datagrams, with no limit on how many are lost.
     */
    public UnreliableDatagramTransport(DatagramTransport transport, Random random,
                                       int percentPacketLossReceiving, int percentPacketLossSending)
    {
        this(transport, random, percentPacketLossReceiving, percentPacketLossSending, Integer.MAX_VALUE,
            Integer.MAX_VALUE);
    }

    /**
     * Lose the given percentages of datagrams, but no more than the given number in each direction, after which
     * the transport is reliable in that direction. The limit bounds how long a run can take: each lost datagram
     * costs at most one resend cycle, and the resend interval doubles with each cycle.
     */
    public UnreliableDatagramTransport(DatagramTransport transport, Random random,
                                       int percentPacketLossReceiving, int percentPacketLossSending,
                                       int maxDroppedReceiving, int maxDroppedSending)
    {
        if (maxDroppedReceiving < 0)
        {
            throw new IllegalArgumentException("'maxDroppedReceiving' cannot be negative");
        }
        if (maxDroppedSending < 0)
        {
            throw new IllegalArgumentException("'maxDroppedSending' cannot be negative");
        }

        this.transport = transport;
        this.random = random;
        this.maxDroppedReceiving = maxDroppedReceiving;
        this.maxDroppedSending = maxDroppedSending;

        setPacketLoss(percentPacketLossReceiving, percentPacketLossSending);
    }

    /**
     * Change the loss rates, e.g. to make the transport reliable once a handshake has completed.
     */
    public void setPacketLoss(int percentPacketLossReceiving, int percentPacketLossSending)
    {
        if (percentPacketLossReceiving < 0 || percentPacketLossReceiving > 100)
        {
            throw new IllegalArgumentException("'percentPacketLossReceiving' out of range");
        }
        if (percentPacketLossSending < 0 || percentPacketLossSending > 100)
        {
            throw new IllegalArgumentException("'percentPacketLossSending' out of range");
        }

        this.percentPacketLossReceiving = percentPacketLossReceiving;
        this.percentPacketLossSending = percentPacketLossSending;
    }

    public int getReceiveLimit()
        throws IOException
    {
        return transport.getReceiveLimit();
    }

    public int getSendLimit()
        throws IOException
    {
        return transport.getSendLimit();
    }

    public int receive(byte[] buf, int off, int len, int waitMillis)
        throws IOException
    {
        long endMillis = System.currentTimeMillis() + waitMillis;
        for (;;)
        {
            int length = transport.receive(buf, off, len, waitMillis);
            if (length < 0 || !lostPacketReceiving())
            {
                return length;
            }

            System.out.println("PACKET LOSS (" + length + " byte packet not received)");

            long now = System.currentTimeMillis();
            if (now >= endMillis)
            {
                return -1;
            }

            waitMillis = (int)(endMillis - now);
        }
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        if (lostPacketSending())
        {
            System.out.println("PACKET LOSS (" + len + " byte packet not sent)");
        }
        else
        {
            transport.send(buf, off, len);
        }
    }

    public void close()
        throws IOException
    {
        transport.close();
    }

    private synchronized boolean lostPacketReceiving()
    {
        if (droppedReceiving >= maxDroppedReceiving || !lostPacket(percentPacketLossReceiving))
        {
            return false;
        }

        if (++droppedReceiving == maxDroppedReceiving)
        {
            System.out.println("PACKET LOSS LIMIT REACHED (" + maxDroppedReceiving + " packets not received)");
        }
        return true;
    }

    private synchronized boolean lostPacketSending()
    {
        if (droppedSending >= maxDroppedSending || !lostPacket(percentPacketLossSending))
        {
            return false;
        }

        if (++droppedSending == maxDroppedSending)
        {
            System.out.println("PACKET LOSS LIMIT REACHED (" + maxDroppedSending + " packets not sent)");
        }
        return true;
    }

    private boolean lostPacket(int percentPacketLoss)
    {
        return percentPacketLoss > 0 && random.nextInt(100) < percentPacketLoss;
    }
}
