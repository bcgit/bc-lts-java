package org.bouncycastle.pkix;

import java.util.Enumeration;

import junit.framework.TestResult;

public class PrintResults
{
    public static void printResult(TestResult result)
    {
        if (result.failureCount() > 0)
        {
            Enumeration r = result.failures();
            while (r.hasMoreElements())
            {
                // -DM System.out.println
                System.out.println(r.nextElement());
            }
        }

        if (result.errorCount() > 0)
        {
            Enumeration r = result.errors();
            while (r.hasMoreElements())
            {
                // -DM System.out.println
                System.out.println(r.nextElement());
            }
        }

        if (!result.wasSuccessful())
        {
            // -DM System.exit
            System.exit(1);
        }
    }
}
