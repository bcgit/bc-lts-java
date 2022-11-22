package org.bouncycastle.util;

public class Skip
{
    /**
     * Returns true if a property is not set, "false" or does not contain [contains]
     *
     * @param property The property
     * @param contains search string
     * @return true if a property is not set, "false" or does not contain [contains]
     */
    public static boolean isNotSkipped(String property, String contains)
    {
        String prop = System.getProperty(property);
        if (prop == null)
        {
            return true;
        }

        if ("false".equals(prop))
        {
            return true;
        }

        if (!prop.contains(contains))
        {
            return true;
        }

        return false;
    }
}
