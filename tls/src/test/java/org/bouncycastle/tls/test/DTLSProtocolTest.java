package org.bouncycastle.tls.test;

import java.util.Random;

import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSRequest;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DTLSVerifier;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

import junit.framework.TestCase;

public class DTLSProtocolTest
    extends TestCase
{
    /**
     * A full handshake, with client authentication, at 10% packet loss in each direction.
     */
    public void testClientServer() throws Exception
    {
        MockDTLSClient client = new MockDTLSClient(null);
        MockDTLSServer server = new MockDTLSServer();

        implTestClientServer(client, server, 10);
    }

    /**
     * A full handshake, with client authentication, under heavy loss: most flights need several attempts.
     */
    public void testClientServerHighLoss() throws Exception
    {
        MockDTLSClient client = new MockDTLSClient(null);
        MockDTLSServer server = new MockDTLSServer();

        implTestClientServer(client, server, 25);
    }

    /**
     * @param handshakePacketLossPercent percentage of datagrams the client's transport loses, in each direction,
     *                                   while the handshake is in progress. The transport becomes reliable once
     *                                   the client's handshake completes, since application data is never
     *                                   retransmitted and the echo phase requires every datagram to arrive. A
     *                                   lossy handshake resends quickly, so that the flights that need several
     *                                   attempts keep the run short.
     */
    private void implTestClientServer(MockDTLSClient client, MockDTLSServer server, int handshakePacketLossPercent)
        throws Exception
    {
        if (handshakePacketLossPercent > 0)
        {
            client.setHandshakeResendTimeMillis(100);
            server.setHandshakeResendTimeMillis(100);
        }

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        UnreliableDatagramTransport lossyTransport = new UnreliableDatagramTransport(clientTransport, new Random(),
            handshakePacketLossPercent, handshakePacketLossPercent, TlsTestConfig.DTLS_MAX_DROPPED_DATAGRAMS,
            TlsTestConfig.DTLS_MAX_DROPPED_DATAGRAMS);
        clientTransport = lossyTransport;

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        HandshakeGuardDatagramTransport guard = new HandshakeGuardDatagramTransport(clientTransport, lossyTransport,
            serverThread);
        clientTransport = guard;

        DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);
        guard.notifyHandshakeComplete();

        for (int i = 1; i <= 10; ++i)
        {
            byte[] data = new byte[i];
            Arrays.fill(data, (byte)i);
            dtlsClient.send(data, 0, data.length);
        }

        byte[] buf = new byte[dtlsClient.getReceiveLimit()];
        while (dtlsClient.receive(buf, 0, buf.length, 100) >= 0)
        {
        }

        dtlsClient.close();

        serverThread.shutdown();
    }

    static class ServerThread
        extends Thread
    {
        private final DTLSServerProtocol serverProtocol;
        private final TlsServer server;
        private final DatagramTransport serverTransport;
        private volatile boolean isShutdown = false;

        ServerThread(DTLSServerProtocol serverProtocol, TlsServer server, DatagramTransport serverTransport)
        {
            this.serverProtocol = serverProtocol;
            this.server = server;
            this.serverTransport = serverTransport;
        }

        public void run()
        {
            try
            {
                TlsCrypto serverCrypto = server.getCrypto();

                DTLSRequest request = null;

                // Use DTLSVerifier to require a HelloVerifyRequest cookie exchange before accepting
                {
                    DTLSVerifier verifier = new DTLSVerifier(serverCrypto);

                    // NOTE: Test value only - would typically be the client IP address
                    byte[] clientID = Strings.toUTF8ByteArray("MockDtlsClient");

                    int receiveLimit = serverTransport.getReceiveLimit();
                    int dummyOffset = serverCrypto.getSecureRandom().nextInt(16) + 1;
                    byte[] buf = new byte[dummyOffset + serverTransport.getReceiveLimit()];

                    do
                    {
                        if (isShutdown)
                            return;

                        int length = serverTransport.receive(buf, dummyOffset, receiveLimit, 100);
                        if (length > 0)
                        {
                            request = verifier.verifyRequest(clientID, buf, dummyOffset, length, serverTransport);
                        }
                    }
                    while (request == null);
                }

                // NOTE: A real server would handle each DTLSRequest in a new task/thread and continue accepting
                {
                    DTLSTransport dtlsTransport = serverProtocol.accept(server, serverTransport, request);
                    byte[] buf = new byte[dtlsTransport.getReceiveLimit()];
                    while (!isShutdown)
                    {
                        int length = dtlsTransport.receive(buf, 0, buf.length, 100);
                        if (length >= 0)
                        {
                            dtlsTransport.send(buf, 0, length);
                        }
                    }
                    dtlsTransport.close();
                }
            }
            catch (Exception e)
            {
                e.printStackTrace();
            }
        }

        void shutdown()
            throws InterruptedException
        {
            if (!isShutdown)
            {
                isShutdown = true;
                this.join();
            }
        }
    }
}
