package org.bouncycastle.jsse.provider.test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

import org.bouncycastle.jsse.BCSSLEngine;

import junit.framework.TestCase;

/**
 * Runs against the built multi-release jar on the newest JDK, so that the root
 * ProvSSLContextSpi is paired with the META-INF/versions/9 SSLEngineUtil the way it is
 * in a deployment - the pairing behind the 1.86 NoSuchMethodError on
 * SSLContext.createSSLEngine() (github #2448), which no test running against the class
 * directories can see.
 */
public class SSLEngineMRTest
    extends TestCase
{
    protected void setUp()
    {
        ProviderUtils.setupLowPriority(false);
    }

    public void testCreateSSLEngine()
        throws Exception
    {
        SSLContext sslContext = SSLContext.getInstance("TLS", ProviderUtils.PROVIDER_NAME_BCJSSE);
        sslContext.init(null, null, null);

        SSLEngine engine = sslContext.createSSLEngine();
        assertTrue(engine instanceof BCSSLEngine);
        // On JDK 9+ the versions/9 SSLEngineUtil must have been the one consulted.
        assertEquals("org.bouncycastle.jsse.provider.ProvSSLEngine_9", engine.getClass().getName());

        SSLEngine peerEngine = sslContext.createSSLEngine("localhost", 443);
        assertTrue(peerEngine instanceof BCSSLEngine);
        assertEquals("localhost", peerEngine.getPeerHost());
        assertEquals(443, peerEngine.getPeerPort());
    }
}
