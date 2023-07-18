package org.bouncycastle.crypto;



import org.bouncycastle.util.dispose.NativeDisposer;
import org.bouncycastle.util.dispose.NativeReference;

public abstract class PacketCipherNativeEngine
    implements PacketCipher
{
//    protected class RefWrapper
//        extends NativeReference
//    {
//        public RefWrapper(long reference, String name)
//        {
//            super(reference, name);
//        }
//
//        @Override
//        public Runnable createAction()
//        {
//            return new Disposer(reference);
//        }
//
//    }
//
//    private class Disposer
//        extends NativeDisposer
//    {
//        Disposer(long ref)
//        {
//            super(ref);
//        }
//
//        @Override
//        protected void dispose(long reference)
//        {
//        }
//    }
}
