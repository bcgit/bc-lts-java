package org.bouncycastle.tls.test;

import org.bouncycastle.tls.DTLSClientProtocol;
import org.bouncycastle.tls.DTLSServerProtocol;
import org.bouncycastle.tls.DTLSTransport;
import org.bouncycastle.tls.DatagramTransport;
import org.bouncycastle.tls.TlsServer;
import org.bouncycastle.tls.TlsTimeoutException;
import org.bouncycastle.util.Arrays;

import junit.framework.TestCase;

public class DTLSPSKProtocolTest
    extends TestCase
{
    /**
     * The budget these two tests hand the peers. Short, because the handshake under test is one
     * that cannot complete and the test is waiting for it to give up - the peers' own default is
     * long, so that the tests which expect a handshake to SUCCEED are not asserting that the
     * machine was fast enough.
     */
    private static final int TIMEOUT_MILLIS = 1000;

    public void testBadClientKeyTimeout() throws Exception
    {
        MockPSKDTLSClient client = new MockPSKDTLSClient(null, true);
        MockPSKDTLSServer server = new MockPSKDTLSServer();

        client.setHandshakeTimeoutMillis(TIMEOUT_MILLIS);
        server.setHandshakeTimeoutMillis(TIMEOUT_MILLIS);

        implTestKeyMismatch(client, server);
    }

    public void testBadServerKeyTimeout() throws Exception
    {
        MockPSKDTLSClient client = new MockPSKDTLSClient(null);
        MockPSKDTLSServer server = new MockPSKDTLSServer(true);

        client.setHandshakeTimeoutMillis(TIMEOUT_MILLIS);
        server.setHandshakeTimeoutMillis(TIMEOUT_MILLIS);

        implTestKeyMismatch(client, server);
    }

    public void testClientServer() throws Exception
    {
        MockPSKDTLSClient client = new MockPSKDTLSClient(null);
        MockPSKDTLSServer server = new MockPSKDTLSServer();

        // The mocks' default 1 second handshake timeout is for the key-mismatch tests; a lossy handshake needs longer
        client.setHandshakeTimeoutMillis(30000);
        server.setHandshakeTimeoutMillis(30000);

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        // 10% packet loss in each direction during the handshake, to exercise handshake retransmission. The
        // transport becomes reliable once the handshake completes, since application data is never retransmitted.
        UnreliableDatagramTransport lossyTransport = new UnreliableDatagramTransport(clientTransport,
            client.getCrypto().getSecureRandom(), 10, 10, TlsTestConfig.DTLS_MAX_DROPPED_DATAGRAMS,
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

    private void implTestKeyMismatch(MockPSKDTLSClient client, MockPSKDTLSServer server) throws Exception
    {
        // The client must be the end that times out: a server timeout would reach the client as an alert first
        server.setHandshakeTimeoutMillis(2 * client.getHandshakeTimeoutMillis());

        DTLSClientProtocol clientProtocol = new DTLSClientProtocol();
        DTLSServerProtocol serverProtocol = new DTLSServerProtocol();

        MockDatagramAssociation network = new MockDatagramAssociation(1500);

        ServerThread serverThread = new ServerThread(serverProtocol, server, network.getServer());
        serverThread.start();

        DatagramTransport clientTransport = network.getClient();

        // Don't use unreliable transport because we are focused on timeout due to bad PSK
//        clientTransport = new UnreliableDatagramTransport(clientTransport, client.getCrypto().getSecureRandom(), 0, 0);

        clientTransport = new LoggingDatagramTransport(clientTransport, System.out);

        Exception clientFailure = null;

        try
        {
            DTLSTransport dtlsClient = clientProtocol.connect(client, clientTransport);
            dtlsClient.close();
        }
        catch (Exception e)
        {
            clientFailure = e;
        }
        finally
        {
            clientTransport.close();
        }

        serverThread.shutdown();

        // The PSKs do not match, so the handshake cannot complete and the client runs out of patience
        assertNotNull("Handshake unexpectedly succeeded with mismatched PSKs", clientFailure);
        assertTrue("Expected a handshake timeout, client failed with: " + clientFailure,
            clientFailure instanceof TlsTimeoutException);
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
                DTLSTransport dtlsServer = serverProtocol.accept(server, serverTransport);
                byte[] buf = new byte[dtlsServer.getReceiveLimit()];
                while (!isShutdown)
                {
                    int length = dtlsServer.receive(buf, 0, buf.length, 100);
                    if (length >= 0)
                    {
                        dtlsServer.send(buf, 0, length);
                    }
                }
                dtlsServer.close();
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
