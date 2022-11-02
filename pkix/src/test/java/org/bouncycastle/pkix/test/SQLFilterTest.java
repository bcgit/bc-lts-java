
package org.bouncycastle.pkix.test;

import junit.framework.TestCase;
import org.bouncycastle.pkix.util.filter.Filter;
import org.bouncycastle.pkix.util.filter.SQLFilter;

public class SQLFilterTest extends TestCase 
{

    private static final String test1 = "\'\"=-/\\;\r\n";

    public void testDoFilter() 
    {
        Filter filter = new SQLFilter();
        assertEquals("encode special charaters","\\\'\\\"\\=\\-\\/\\\\\\;\\r\\n",filter.doFilter(test1));
    }

}
