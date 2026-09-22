package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * A sorting list - byte[] are sorted in ascending order.
 */
public class SortedHashList
{
    private static final Comparator<byte[]> hashComp = new ByteArrayComparator();

    private final List<byte[]> baseList = new ArrayList<byte[]>();

    public SortedHashList()
    {
    }

    public byte[] getFirst()
    {
        if (baseList.isEmpty())
        {
            throw new NoSuchElementException();
        }

        byte[] first = (byte[])baseList.get(0);

        for (int i = 1; i != baseList.size(); i++)
        {
            byte[] next = (byte[])baseList.get(i);

            // strictly less than, so the earliest added of a set of equal hashes is returned
            if (hashComp.compare(next, first) < 0)
            {
                first = next;
            }
        }

        return first;
    }

    public void add(byte[] hash)
    {
        baseList.add(hash);
    }

    public int size()
    {
        return baseList.size();
    }

    /**
     * Return the hashes added so far in ascending order.
     * <p>
     * The sort is stable, so hashes comparing equal come back in the order they were added in.
     *
     * @return a sorted list of the hashes added.
     */
    public List<byte[]> toList()
    {
        List<byte[]> sorted = new ArrayList<byte[]>(baseList);

        Collections.sort(sorted, hashComp);

        return sorted;
    }
}
