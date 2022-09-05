package org.bouncycastle.util.dispose;

/**
 * Instances of this can be added to the CryptoServicesRegister reference queue
 * to ensure the dispose method is called before GC.
 * This exists because finalize has been deprecated.
 */
public interface Disposable
{
    void dispose();
}
