package org.bouncycastle.crypto.digests;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.bouncycastle.util.test.SimpleTest;
import org.bouncycastle.util.test.TestResult;

/**
 * Blake2b keeps a 128-bit input-byte counter (t0/t1) that it XORs into the compression IV. The
 * low word is advanced once per compression via a private helper that also has to detect when
 * that addition wraps 2^64 and carry into the high word. Driving that carry through the public
 * API would mean hashing on the order of 2^64 bytes, so this test reaches the private counter
 * fields directly (via reflection) to place t0 right at the wrap boundary and confirms the carry
 * fires - and, as a regression guard, that it fires for amounts that do NOT happen to land the
 * wrapped sum on exactly zero (a naive "if (t0 == 0) t1++" check - the bug this replaced - passes
 * only in that one special case).
 */
public class Blake2bCounterOverflowTest
    extends SimpleTest
{
    public String getName()
    {
        return "Blake2bCounterOverflow";
    }

    public void performTest()
        throws Exception
    {
        // Case 1: wrap lands exactly on zero (the case the old buggy check happened to get right).
        checkCarry(-128L /* 2^64 - 128 */, 128, 0L, 1L);

        // Case 2: wrap does NOT land on zero - the case the old "if (t0 == 0)" check missed.
        checkCarry(-40L /* 2^64 - 40 */, 128, 88L, 1L);

        // Case 3: no wrap at all - t1 must stay put.
        checkCarry(1000L, 128, 1128L, 0L);

        // Case 4: adding zero must never spuriously carry.
        checkCarry(-1L /* 2^64 - 1 */, 0, -1L, 0L);
    }

    private void checkCarry(long startT0, int count, long expectedT0, long expectedT1Delta)
        throws Exception
    {
        Blake2bDigest digest = new Blake2bDigest(512);

        Field t0Field = Blake2bDigest.class.getDeclaredField("t0");
        Field t1Field = Blake2bDigest.class.getDeclaredField("t1");
        t0Field.setAccessible(true);
        t1Field.setAccessible(true);

        t0Field.setLong(digest, startT0);
        t1Field.setLong(digest, 0L);

        Method increment = Blake2bDigest.class.getDeclaredMethod("incrementCounter", int.class);
        increment.setAccessible(true);
        increment.invoke(digest, count);

        long resultT0 = t0Field.getLong(digest);
        long resultT1 = t1Field.getLong(digest);

        isEquals("t0 for startT0=" + startT0 + " count=" + count, expectedT0, resultT0);
        isEquals("t1 carry for startT0=" + startT0 + " count=" + count, expectedT1Delta, resultT1);
    }

    public static void main(String[] args)
    {
        TestResult result = new Blake2bCounterOverflowTest().perform();

        System.out.println(result);
    }
}
