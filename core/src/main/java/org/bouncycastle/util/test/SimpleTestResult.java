package org.bouncycastle.util.test;

import org.bouncycastle.util.Strings;

import java.io.PrintWriter;
import java.io.StringWriter;

public class SimpleTestResult implements TestResult
{
    private static final String SEPARATOR = Strings.lineSeparator();

    private boolean success;
    private String message;
    private Throwable exception;

    public SimpleTestResult(boolean success, String message)
    {
        this.success = success;
        this.message = message;
    }

    public SimpleTestResult(boolean success, String message, Throwable exception)
    {
        this.success = success;
        this.message = message;
        this.exception = exception;
    }

    public static TestResult successful(
            Test test,
            String message)
    {
        return new SimpleTestResult(true, test.getName() + ": " + message);
    }

    public static TestResult failed(
            Test test,
            String message)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message);
    }

    public static TestResult failed(
            Test test,
            String message,
            Throwable t)
    {
        return new SimpleTestResult(false, test.getName() + ": " + message, t);
    }

    public static TestResult failed(
            Test test,
            String message,
            Object expected,
            Object found)
    {
        return failed(test, message + SEPARATOR + "Expected: " + expected + SEPARATOR + "Found   : " + found);
    }

    public static String failedMessage(String algorithm, String testName, String expected,
                                       String actual)
    {
        StringBuffer sb = new StringBuffer(algorithm);
        sb.append(" failing ").append(testName);
        sb.append(SEPARATOR).append("    expected: ").append(expected);
        sb.append(SEPARATOR).append("    got     : ").append(actual);

        return sb.toString();
    }

    public boolean isSuccessful()
    {
        return success;
    }

    public String toString()
    {
        if (exception != null)
        {
            StringWriter sw = new StringWriter();
            PrintWriter pw = new PrintWriter(sw);
            this.exception.printStackTrace(pw);
            pw.flush();
            pw.close();
            message = message + "\n" + sw;

        }
        return message;
    }

    public Throwable getException()
    {
        return exception;
    }
}
