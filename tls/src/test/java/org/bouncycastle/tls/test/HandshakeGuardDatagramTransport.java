package org.bouncycastle.tls.test;

import java.io.IOException;

import org.bouncycastle.tls.DatagramTransport;

/**
 * The outermost wrapper of a test client's transport, applying the handshake-phase policy of the loopback tests.
 * While the handshake is in progress, a receive that comes up empty after the server thread has ended, or after
 * the handshake deadline, throws rather than letting a client with no handshake timeout wait forever. Once
 * {@link #notifyHandshakeComplete()} is called, any handshake packet loss on the wrapped
 * {@link UnreliableDatagramTransport} is switched off, since application data is never retransmitted.
 */
class HandshakeGuardDatagramTransport
    implements DatagramTransport
{
    static final int HANDSHAKE_DEADLINE_MILLIS = 60000;

    private final DatagramTransport transport;
    private final UnreliableDatagramTransport lossyTransport;
    private final Thread serverThread;
    private final long handshakeDeadline;

    private volatile boolean inHandshake = true;

    /**
     * @param transport      the transport to wrap.
     * @param lossyTransport the lossy layer beneath it, to be made reliable when the handshake completes, or null.
     * @param serverThread   the server's thread; if it has ended while the handshake is in progress there is no
     *                       longer any prospect of the handshake completing.
     */
    HandshakeGuardDatagramTransport(DatagramTransport transport, UnreliableDatagramTransport lossyTransport,
        Thread serverThread)
    {
        this.transport = transport;
        this.lossyTransport = lossyTransport;
        this.serverThread = serverThread;
        this.handshakeDeadline = System.currentTimeMillis() + HANDSHAKE_DEADLINE_MILLIS;
    }

    void notifyHandshakeComplete()
    {
        inHandshake = false;
        if (lossyTransport != null)
        {
            lossyTransport.setPacketLoss(0, 0);
        }
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
        int length = transport.receive(buf, off, len, waitMillis);
        if (length < 0)
        {
            checkHandshakeStalled();
        }
        return length;
    }

    public void send(byte[] buf, int off, int len)
        throws IOException
    {
        transport.send(buf, off, len);
    }

    public void close()
        throws IOException
    {
        transport.close();
    }

    /**
     * Nothing arrived within the wait: give up on the handshake if there is no longer any prospect of it
     * completing.
     */
    private void checkHandshakeStalled()
        throws IOException
    {
        if (!inHandshake)
        {
            return;
        }

        if (!serverThread.isAlive())
        {
            throw new IOException("DTLS server ended during the handshake");
        }

        if (System.currentTimeMillis() >= handshakeDeadline)
        {
            throw new IOException("DTLS handshake did not complete within " + HANDSHAKE_DEADLINE_MILLIS + "ms");
        }
    }
}
