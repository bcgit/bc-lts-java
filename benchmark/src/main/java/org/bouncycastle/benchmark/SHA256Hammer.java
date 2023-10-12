package org.bouncycastle.benchmark;


import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

public class SHA256Hammer implements Runnable
{
    private static SecureRandom rand = new SecureRandom();

    public static void main(String[] args) throws Exception
    {
        Security.addProvider(new BouncyCastleProvider());

        for (int t = 0; t < 200; t++)
        {
            Thread thread = new Thread(new SHA256Hammer());
            thread.start();
        }
    }


    @Override
    public void run()
    {

        byte[] key = new byte[32];
        rand.nextBytes(key);
        for (; ; )
        {
            try
            {
                Mac mac = Mac.getInstance("HMAC-SHA256", BouncyCastleProvider.PROVIDER_NAME);
                mac.init(new SecretKeySpec(key,"HMAC-SHA256"));
                byte[] msg = new byte[rand.nextInt(8192)+1];
                mac.update(msg);
                byte[] dig = mac.doFinal();
                msg[0] ^= dig[0];
                key[0] ^= dig[1];
            }
            catch (Exception ex)
            {
                ex.printStackTrace();
                throw new RuntimeException(ex.getMessage(), ex);
            }
        }

    }
}
