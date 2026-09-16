package org.bouncycastle.pkix.jcajce;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import junit.framework.TestCase;

/**
 * removePolicyNode is reached from the RFC 5280 policy processing with a valid-policy-tree that
 * may already have been pruned to null. It must answer that case without looking at the node it
 * was asked to remove - there is nothing to remove from, and the node need not be usable.
 * <p>
 * The same helper is duplicated in prov's CertPathValidatorUtilities; these cases pin the two to
 * the same behaviour.
 */
public class PolicyNodeRemovalTest
    extends TestCase
{
    // depth matters: removePolicyNodeRecurse removes a node from policyNodes[node.getDepth()],
    // so a node's depth has to match the level list it was put in
    private static PKIXPolicyNode node(PKIXPolicyNode parent, int depth, String policy)
    {
        HashSet expected = new HashSet();
        expected.add(policy);

        return new PKIXPolicyNode(new ArrayList(), depth, expected, parent, new HashSet(), policy, false);
    }

    public void testNullTreeReturnsNullWithoutTouchingTheNode()
    {
        List[] policyNodes = new List[]{ new ArrayList() };

        // a null node is the sharpest form of "must not be dereferenced": before the ordering fix
        // this raised NullPointerException instead of returning null
        assertNull(CertPathValidatorUtilities.removePolicyNode(null, policyNodes, null));

        // and with a real node the answer is the same, and nothing is removed
        PKIXPolicyNode parent = node(null, 0, "2.5.29.32.0");
        PKIXPolicyNode child = node(parent, 0, "1.2.3.4");
        parent.addChild(child);
        policyNodes[0].add(child);

        assertNull(CertPathValidatorUtilities.removePolicyNode(null, policyNodes, child));
        assertTrue("child removed from a null tree", parent.hasChildren());
        assertEquals("policy nodes cleared for a null tree", 1, policyNodes[0].size());
    }

    public void testRemovingARootClearsEveryLevel()
    {
        PKIXPolicyNode root = node(null, 0, "2.5.29.32.0");

        List[] policyNodes = new List[]{ new ArrayList(), new ArrayList() };
        policyNodes[0].add(root);
        policyNodes[1].add(node(root, 1, "1.2.3.4"));

        // a node with no parent is the root: the whole tree goes
        assertNull(CertPathValidatorUtilities.removePolicyNode(root, policyNodes, root));

        for (int i = 0; i != policyNodes.length; i++)
        {
            assertTrue("level " + i + " not cleared", policyNodes[i].isEmpty());
        }
    }

    public void testRemovingAChildLeavesTheTree()
    {
        PKIXPolicyNode root = node(null, 0, "2.5.29.32.0");
        PKIXPolicyNode child = node(root, 1, "1.2.3.4");

        root.addChild(child);

        List[] policyNodes = new List[]{ new ArrayList(), new ArrayList() };
        policyNodes[0].add(root);
        policyNodes[1].add(child);

        assertSame(root, CertPathValidatorUtilities.removePolicyNode(root, policyNodes, child));

        assertFalse("child not detached from its parent", root.hasChildren());
        assertFalse("child left in the level list", policyNodes[1].contains(child));
        assertTrue("root removed along with the child", policyNodes[0].contains(root));
    }
}
