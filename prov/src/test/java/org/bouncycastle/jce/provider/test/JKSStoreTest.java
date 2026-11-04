package org.bouncycastle.jce.provider.test;

import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;

import org.bouncycastle.jcajce.provider.keystore.util.AdaptingKeyStoreSpi;
import org.bouncycastle.jcajce.provider.keystore.util.JKSKeyStoreSpi;
import org.bouncycastle.jcajce.util.BCJcaJceHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.test.SimpleTest;

public class JKSStoreTest
    extends SimpleTest
{
    public String getName()
    {
        return "JKSStore";
    }

    public void performTest()
        throws Exception
    {
        testLoadTruncatedStore();
        testLoadTruncatedStoreThroughKeyStore();
    }

    private void testLoadTruncatedStore()
        throws Exception
    {
        // shorter than the checksum alone, and shorter than the header plus the checksum
        int[] lengths = new int[]{ 0, 4, 19, 31 };

        for (int i = 0; i != lengths.length; i++)
        {
            byte[] store = Arrays.copyOfRange(PKCS12StoreTest.JKS_Store, 0, lengths[i]);

            implLoadTruncatedStore(store, null);
            implLoadTruncatedStore(store, PKCS12StoreTest.JKS_TEST_PWD);
        }
    }

    private void implLoadTruncatedStore(byte[] store, char[] password)
        throws Exception
    {
        JKSKeyStoreSpi jksStore = new JKSKeyStoreSpi(new BCJcaJceHelper());

        try
        {
            jksStore.engineLoad(new ByteArrayInputStream(store), password);

            fail("truncated store of " + store.length + " bytes accepted");
        }
        catch (EOFException e)
        {
            // expected
        }
    }

    /**
     * The JKS store is reached through the compatibility probe in AdaptingKeyStoreSpi, so a
     * truncated store has to leave KeyStore.load() by way of its declared IOException rather
     * than an ArrayIndexOutOfBoundsException (github #2451).
     */
    private void testLoadTruncatedStoreThroughKeyStore()
        throws Exception
    {
        String compatValue = System.getProperty(AdaptingKeyStoreSpi.COMPAT_OVERRIDE);

        System.setProperty(AdaptingKeyStoreSpi.COMPAT_OVERRIDE, "true");

        try
        {
            int[] lengths = new int[]{ 0, 4, 19, 31 };

            for (int i = 0; i != lengths.length; i++)
            {
                byte[] store = Arrays.copyOfRange(PKCS12StoreTest.JKS_Store, 0, lengths[i]);

                KeyStore ks = KeyStore.getInstance("PKCS12", "BC");

                try
                {
                    ks.load(new ByteArrayInputStream(store), PKCS12StoreTest.JKS_TEST_PWD);

                    fail("truncated store of " + store.length + " bytes accepted");
                }
                catch (IOException e)
                {
                    // expected
                }
            }
        }
        finally
        {
            if (compatValue == null)
            {
                System.getProperties().remove(AdaptingKeyStoreSpi.COMPAT_OVERRIDE);
            }
            else
            {
                System.setProperty(AdaptingKeyStoreSpi.COMPAT_OVERRIDE, compatValue);
            }
        }
    }

    public static void main(
        String[] args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new JKSStoreTest());
    }
}
