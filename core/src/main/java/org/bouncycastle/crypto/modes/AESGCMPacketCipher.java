package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.PacketCipher;
import org.bouncycastle.crypto.PacketCipherException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

public class AESGCMPacketCipher
    implements PacketCipher
{
    private GCMModeCipher gcm;
    CipherParameters parameters;
    boolean forEncryption;

    public static AESGCMPacketCipher newInstance()
    {
        return new AESGCMPacketCipher();
    }

    private AESGCMPacketCipher()
    {
        gcm = GCMBlockCipher.newInstance(AESEngine.newInstance());
    }

    @Override
    public int getOutputSize(boolean forEncryption, CipherParameters parameters, int len)
    {
        init(forEncryption, parameters);
        return gcm.getOutputSize(len);
    }


    @Override
    public int processPacket(boolean forEncryption, CipherParameters parameters, byte[] input, int inOff, int len,
                             byte[] output, int outOff)
        throws PacketCipherException
    {
       /*
            First round of work:
            - Use java GCM, create new instance of GCM, initialise it, then update and doFinal.

            Important:
                If at any stage there is an exception thrown it must zero any data it has written out to output

        */
        try
        {
            init(forEncryption, parameters);
        }
        catch (Throwable ex)
        {
            throw PacketCipherException.from(ex);
        }
        Throwable exceptionThrown = null;
        int written = 0;
        try
        {
            written += gcm.processBytes(input, inOff, len, output, outOff);
            written += gcm.doFinal(output, written + outOff);

        }
        catch (Throwable t)
        {
            exceptionThrown = t;
        }
        gcm.reset();
        if (exceptionThrown != null)
        {
            Arrays.fill(output, (byte)0);
            throw PacketCipherException.from(exceptionThrown);
        }
        return written;
    }

    private void init(boolean forEncryption, CipherParameters parameters)
    {
        // If the parameters keep the same, we need to get a new instance
        if ((parameters instanceof AEADParameters && this.parameters instanceof AEADParameters &&
            Arrays.areEqual(((AEADParameters)parameters).getKey().getKey(), ((AEADParameters)this.parameters).getKey().getKey()))
            || (parameters instanceof ParametersWithIV && this.parameters instanceof ParametersWithIV &&
            Arrays.areEqual(((KeyParameter)(((ParametersWithIV)parameters).getParameters())).getKey(),
                ((KeyParameter)(((ParametersWithIV)this.parameters).getParameters())).getKey())))
        {
            gcm = GCMBlockCipher.newInstance(gcm.getUnderlyingCipher());
            gcm.init(forEncryption, parameters);
//            if (parameters instanceof AEADParameters)
//            {
//                AEADParameters param = (AEADParameters)parameters;
//                gcm.init(forEncryption, new AEADParameters(null, param.getMacSize(), param.getNonce()));
//            }
//            else if (parameters instanceof ParametersWithIV)
//            {
//                ParametersWithIV param = (ParametersWithIV)parameters;
//                gcm.init(forEncryption, new ParametersWithIV(null, param.getIV()));
//            }
//            else
//            {
//                throw new IllegalArgumentException("invalid parameters passed to GCM");
//            }
        }
        else
        {
            gcm.init(forEncryption, parameters);
            this.parameters = parameters;
            this.forEncryption = forEncryption;

        }
    }
}
