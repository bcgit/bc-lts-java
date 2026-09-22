package org.bouncycastle.tsp.ers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;

/**
 * A sorting list - byte[] are sorted in ascending order.
 */
public class SortedIndexedHashList
{
    private static final Comparator<byte[]> hashComp = new ByteArrayComparator();

    private static final Comparator<IndexedHash> digestComp = new DigestComparator();

    private final List<IndexedHash> baseList = new ArrayList<IndexedHash>();

    public SortedIndexedHashList()
    {
    }

    public IndexedHash getFirst()
    {
        if (baseList.isEmpty())
        {
            throw new NoSuchElementException();
        }

        IndexedHash first = (IndexedHash)baseList.get(0);

        for (int i = 1; i != baseList.size(); i++)
        {
            IndexedHash next = (IndexedHash)baseList.get(i);

            // strictly less than, so the earliest added of a set of equal hashes is returned
            if (digestComp.compare(next, first) < 0)
            {
                first = next;
            }
        }

        return first;
    }

    public void add(IndexedHash hash)
    {
        baseList.add(hash);
    }

    public int size()
    {
        return baseList.size();
    }

    /**
     * Return the hashes added so far in ascending order of digest.
     * <p>
     * The sort is stable, so hashes comparing equal come back in the order they were added in.
     *
     * @return a sorted list of the hashes added.
     */
    public List<IndexedHash> toList()
    {
        List<IndexedHash> sorted = new ArrayList<IndexedHash>(baseList);

        Collections.sort(sorted, digestComp);

        return sorted;
    }

    // takes Objects, as ByteArrayComparator does: the legacy builds strip the type parameters
    // and a compare() declared on IndexedHash then implements nothing.
    private static class DigestComparator
        implements Comparator
    {
        public int compare(Object l, Object r)
        {
            return hashComp.compare(((IndexedHash)l).digest, ((IndexedHash)r).digest);
        }
    }
}
