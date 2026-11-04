package org.bouncycastle.asn1.crmf.test;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.crmf.PKIPublicationInfo;
import org.bouncycastle.asn1.crmf.SinglePubInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.util.test.SimpleTest;


public class PKIPublicationInfoTest
    extends SimpleTest
{
    public static void main(String[] args)
    {
        runTest(new PKIPublicationInfoTest());
    }

    public String getName()
    {
        return "PKIPublicationInfoTest";
    }

    public void performTest()
        throws Exception
    {
        PKIPublicationInfo pkiPubInfo = new PKIPublicationInfo(PKIPublicationInfo.dontPublish);

        isEquals(PKIPublicationInfo.dontPublish, pkiPubInfo.getAction());

        encEqualTest(pkiPubInfo);

        pkiPubInfo = new PKIPublicationInfo(PKIPublicationInfo.dontPublish.getValue());

        isEquals(PKIPublicationInfo.dontPublish, pkiPubInfo.getAction());

        encEqualTest(pkiPubInfo);

        SinglePubInfo singlePubInfo1 = new SinglePubInfo(SinglePubInfo.x500, new GeneralName(new X500Name("CN=TEST")));
        pkiPubInfo = new PKIPublicationInfo(singlePubInfo1);

        isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
        isEquals(1, pkiPubInfo.getPubInfos().length);
        isEquals(singlePubInfo1, pkiPubInfo.getPubInfos()[0]);
        
        encEqualTest(pkiPubInfo);

        SinglePubInfo singlePubInfo2 = new SinglePubInfo(SinglePubInfo.x500, new GeneralName(new X500Name("CN=BLOOT")));

        pkiPubInfo = new PKIPublicationInfo(new SinglePubInfo[] { singlePubInfo1, singlePubInfo2 });

        isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
        isEquals(2, pkiPubInfo.getPubInfos().length);
        isEquals(singlePubInfo1, pkiPubInfo.getPubInfos()[0]);
        isEquals(singlePubInfo2, pkiPubInfo.getPubInfos()[1]);
        
        encEqualTest(pkiPubInfo);

        pkiPubInfo = new PKIPublicationInfo((SinglePubInfo)null);

        isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
        isTrue(null == pkiPubInfo.getPubInfos());

        encEqualTest(pkiPubInfo);

        pkiPubInfo = new PKIPublicationInfo((SinglePubInfo[])null);

        isEquals(PKIPublicationInfo.pleasePublish, pkiPubInfo.getAction());
        isTrue(null == pkiPubInfo.getPubInfos());

        encEqualTest(pkiPubInfo);

        rejectionTests();
    }

    /**
     * RFC 4211 sec. 6.3: pubInfos MUST NOT be present if the action is dontPublish, and the field
     * is SEQUENCE SIZE (1..MAX), so a present one is never empty. Both are rejected on parsing and
     * on construction.
     */
    private void rejectionTests()
        throws IOException
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(PKIPublicationInfo.dontPublish);
        v.add(new DERSequence(new SinglePubInfo(SinglePubInfo.dontCare, null)));

        try
        {
            PKIPublicationInfo.getInstance(new DERSequence(v).getEncoded());
            fail("no exception on dontPublish with pubInfos");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("pubInfos must be absent if action is dontPublish", e.getMessage());
        }

        v = new ASN1EncodableVector();

        v.add(PKIPublicationInfo.pleasePublish);
        v.add(new DERSequence());

        try
        {
            PKIPublicationInfo.getInstance(new DERSequence(v).getEncoded());
            fail("no exception on an empty pubInfos");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("pubInfos must contain at least one SinglePubInfo", e.getMessage());
        }

        try
        {
            new PKIPublicationInfo(new SinglePubInfo[0]);
            fail("no exception on an empty pubInfo array");
        }
        catch (IllegalArgumentException e)
        {
            isEquals("pubInfos must contain at least one SinglePubInfo", e.getMessage());
        }
    }

    private void encEqualTest(PKIPublicationInfo pubInfo)
        throws IOException
    {
        byte[] b = pubInfo.getEncoded();

        PKIPublicationInfo pubInfoResult = PKIPublicationInfo.getInstance(b);

        isEquals(pubInfo, pubInfoResult);
    }
}
