package org.bouncycastle.math;

import junit.framework.TestCase;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.raw.Mul;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;

public class MulTest extends TestCase
{

    @Before
    public void before()
    {
        CryptoServicesRegistrar.getNativeServices();
    }

    private static final ArrayList<Vec> vecs = new ArrayList<>();


    static
    {

        vecs.add(new Vec(
                new long[]{0x2F61DD5526E17E73L},
                new long[]{0x1F1D290518101D43L},
                new long[]{0x6879B6EEE4DF0955L, 0x03422D6002A748EDL}
        ));

        vecs.add(new Vec(
                new long[]{0x43600F9FE0FBB334L, 0x70DA0A546E31B315L},
                new long[]{0x3BD844254F708633L, 0x637007F7C311F267L},
                new long[]{0x52AC9E954531389CL, 0xB42351D6EC97F1A8L, 0xA65C10E1E43EB902L, 0x12A98CDC2DB2D217L}
        ));

        vecs.add(new Vec(
                new long[]{0x278BEC83175FEAD6L, 0x7010E1E0F5AD1121L, 0x7F8733406904EEA5L},
                new long[]{0x47905C8B3EFD8786L, 0x542A8127871C504CL, 0x2155D19B1EB7A51BL},
                new long[]{0xDFBA088C6CD437F4L, 0xE0ADAE0FCC4DEA15L, 0x93C8D7F99C700F09L, 0xEC2237387CA5D92BL,
                        0x62EBE34C4E21FA93L, 0x0F96DEE1B40A6AB9L}
        ));

        vecs.add(new Vec(
                new long[]{0x3F39957D32AA043BL, 0x6F4E937C058F5546L, 0x515DEF4F2CB1D156L, 0x0CDE28D6C8330B5AL},
                new long[]{0x7630D677E1C64995L, 0x60A9C7DA77F9EC1EL, 0x5AFE5B8A088B0A5AL, 0x02E9A379861F8996L},
                new long[]{0x75017490EC5169E7L, 0x2FFC232ED3B3B23BL, 0x9FB3E6FED7582684L, 0xE25FD3B7DDD494F5L,
                        0xF3404BD4B1602C82L, 0x78DEDE82ADBC5C1AL, 0x77DA86BDF59B4F74L, 0x001D12C63930AD28L}
        ));

        vecs.add(new Vec(
                new long[]{0x72B4E4CB4B5E0D2FL, 0x30A97B4D4D03889BL, 0x313F3BD567970554L, 0x2438507AAC2D0A49L,
                        0x05B2FBBC0D9D9E48L},
                new long[]{0x2FA3095452ABD232L, 0x32C2952C01250D99L, 0x725C0DC25FDBEA03L, 0x0F73EB2FC7780F3EL,
                        0x37F453D729E7F14CL},
                new long[]{0x62382FCAB3E0834EL, 0xF308AFDE8E227B42L, 0xA0379016180B7E3AL, 0xA7BD6FF52CDF51B1L,
                        0x912A3E24DC24F532L, 0x847176ACBB111E96L, 0x5529342511BECCF6L, 0x872FFDF76514526DL,
                        0xFB42611EE8AAAA06L, 0x00F6236CD6CB4296L}
        ));

        vecs.add(new Vec(
                new long[]{0x148B52B6E8E5BACFL, 0x201474C4040020ADL, 0x3D31E2FD58045C29L, 0x5A36343B82F51FC7L,
                        0x0D3669A0A3E4EFCDL, 0x0DD413855DA507D1L},
                new long[]{0x32BA65BF79D3AF63L, 0x61C9ACAF5559C128L, 0x1BA2E8F93CE9F065L, 0x39560AF5956ED53FL,
                        0x19B75AABCB7AB688L, 0x47B2D622487173F6L},
                new long[]{0xAD10176633DA5071L, 0x60500DB04659C19CL, 0xB3FDA35AA5B21D0CL, 0x8E7C5BEEDC274F59L,
                        0xA54760F181C09F89L, 0x3E2D114B621DBDF8L, 0xBA1A59BA5E20DD66L, 0x7CEA1CD8853360BFL,
                        0xCE3BC56E6DEB6559L, 0xD93C57E74E7C9553L, 0xFF5AA683B40ACB4CL, 0x0353BB9676E260B9L}
        ));

        vecs.add(new Vec(
                new long[]{0x66F38CC442CB879BL, 0x4BB7D68F5C054B3CL, 0x563A8B02D52340E8L, 0x783D329B8DA80676L,
                        0x600D8E71FD5AA6F8L, 0x4BEFB446519AC7A9L, 0x70C0623C90441A83L},
                new long[]{0x7E21BAA933D7080DL, 0x68CB3CE21F1172C1L, 0x7D2E28D2E153A522L, 0x6359ABC0F0372F9DL,
                        0x7CADCEAB131922AFL, 0x479F43F59D1008BFL, 0x3BE809C80186E22FL},
                new long[]{0xA1F663A8BAB47D2FL, 0x34188960F60310F2L, 0xDBC44F8BF71A0B1BL, 0x5A9B563E45BB415BL,
                        0x4445BC269D55E62CL, 0x1343D9B793F65210L, 0x2559BAB08EA9784EL, 0x0B569B013D3CCA59L,
                        0xC4A63886614B6D08L, 0x10250BE92A20BDAFL, 0x1618FF6631A6A8D0L, 0xBE73C75739C21B7AL,
                        0x68F1C77B6BF50F9FL, 0x0A2A842428346746L}
        ));

        vecs.add(new Vec(
                new long[]{0x4766474592A95483L, 0x0FFB16E0533D7CE1L, 0x55BC510DB52F6AD2L, 0x68E2CEEB58D217ABL,
                        0x68785C32096CA894L, 0x3DC7AE6F4FC453CCL, 0x1C05CF539DC2041AL, 0x098419434109EC42L},
                new long[]{0x3AE7C149ECAEDC71L, 0x0660E5CD40B1E177L, 0x1FB6CBAFAD952BB4L, 0x2E5857F173107EC8L,
                        0x5FA490D1D833172DL, 0x789FA9CF3C93E815L, 0x7F0EFEE9E8BBB266L, 0x5AAD78D42F3B935CL},
                new long[]{0x54EF16A0786EC813L, 0x2A3B8E2A9F5518A0L, 0x020F148824FB0BD0L, 0x7269BB4348D68B8AL,
                        0x758D90A880150BA3L, 0xC3F30983BE8CA7B9L, 0x037EB905D3225111L, 0x67357365606C4E8AL,
                        0xAC43F75FB4B5865CL, 0x84AF508EA27A1354L, 0xCAEB5632AFACB7D3L, 0x95FC0D340420CB31L,
                        0x371E842AC6C7B4D2L, 0xA925BD0E607E36CBL, 0x57B93CBE6CFD0BC1L, 0x02A3FD84BF780276L}
        ));

        vecs.add(new Vec(
                new long[]{0x00FE09E7685C87C5L, 0x1C34DF5A300D9C98L, 0x5D2924909D2ABEACL, 0x5C35A32619E184BFL,
                        0x3C3DB294C1CAE2F6L, 0x30E4F810E6474CE8L, 0x5CDB77B8CCD7B18EL, 0x6FBEA3FB8F26A51CL,
                        0x37F71F7348E9DD0EL},
                new long[]{0x3C0CB73C524552DFL, 0x2085E36D179173A6L, 0x5F31C7888AC09D7BL, 0x4835745E0692694AL,
                        0x19B97CB8116C9D10L, 0x3848D946F89B49E6L, 0x2E377B16808FCE5CL, 0x4A3DBE0BD013DA1AL,
                        0x489BE8C9069AB67CL},
                new long[]{0xED79049444CA5CE3L, 0xD1C883088C5D0BC0L, 0x7CCC0335803E6073L, 0xF3B40DB4B350D69FL,
                        0x0206C71854088992L, 0x8C545DA9197E0B01L, 0x03E505BADB28799EL, 0x53D9FC0F2AF13489L,
                        0x584209FD9CB5747EL, 0x65C880BA64F93D25L, 0x5DB4B55E7A738C1AL, 0xFBE4225ECA018927L,
                        0x279C0712F55541D4L, 0xD4B68E15786FEDB9L, 0x67339AC8693EF055L, 0x6BAE25DAFA92775BL,
                        0x0234C6C666477885L, 0x0C5B0D28413C210FL}
        ));

        vecs.add(new Vec(
                new long[]{0x64E508C423576282L, 0x7385DD89DF92D686L, 0x2D60DABDF6E3ED33L, 0x1882E5AA19A91CDDL,
                        0x612EDFD8D778EA71L, 0x085BF04E96251748L, 0x57F79FA3E31E945FL, 0x41BB76870C816534L,
                        0x7886C4E214D44E06L, 0x0C33D4197CD11C3CL},
                new long[]{0x49664B3000C57085L, 0x7C725EA8BEC54A34L, 0x557925E106583FE2L, 0x176F5AE3BE59283FL,
                        0x0EE4640C07B9B4FFL, 0x44D90E0A29AC3BA5L, 0x41331F038A7C22F0L, 0x111C4393BECC82C4L,
                        0x4C7B3AEB8AE4006FL, 0x04ECDD31A655BD58L},
                new long[]{0x26D8394C4E69498AL, 0xF958C67CCF4497E4L, 0x61EA6AAE5BA1A1C3L, 0xAD169649D8C63CF0L,
                        0x86D1E7AF0968A4EEL, 0x38459ED3E2E9D6B3L, 0x4072BC5F4345B2F7L, 0xD22F9FCF3461A326L,
                        0xAB4C4C9A23B5F0D4L, 0xC14450AF84A9BD61L, 0x29C7272378A7E71DL, 0x452E3C2503D17FF8L,
                        0xC20D1887D0E2DF76L, 0x2B5ADA9E0BBCBFD0L, 0xA1798BC72BDB6AF5L, 0x2E06BE26EF2FA9FDL,
                        0x6D54A3AF4C92A688L, 0x5C3730998D5CD653L, 0x7F4E2E040EB96456L, 0x003408EE123C8C4EL}
        ));

        vecs.add(new Vec(
                new long[]{0x027C70CDB37CD527L, 0x64B335EA6A0E9638L, 0x160B9D222BED20CFL, 0x270D7B1B4078AF14L,
                        0x69926FBB35AAE995L, 0x14240BBF2FEA1F8DL, 0x020B21691CFE0116L, 0x5A04B21C03AC56D2L,
                        0x03C0E738AAE2980FL, 0x4FC3873D79F9AA0DL, 0x0EC3991A6D40908BL},
                new long[]{0x51A9C3FCF369C20AL, 0x5C3E9371825D3A29L, 0x6E11F9FA9401BE58L, 0x328749BE1EB3406DL,
                        0x569A39B7FB098326L, 0x4C5DE3DA3CAF824FL, 0x7126FCF275301441L, 0x1F526D9CA1123D8AL,
                        0x7FD8042FABDB13ADL, 0x1ACFCD7890A53783L, 0x3FF326B526E081EDL},
                new long[]{0xF0FEA4E373500D76L, 0x391EC95AA20961A5L, 0x2F8CF2FFBDD55A06L, 0xA1F36A3197A1031CL,
                        0xC7B58E620BC8F59CL, 0x06242E3CDC6700C5L, 0xD4382E0DC429DCCDL, 0x59B66BA9986CEF7AL,
                        0x6597879EC19F2BC8L, 0x80CD8E369392E474L, 0x9490AE22C35A52BEL, 0x5AEF6656865F5A83L,
                        0x37FA692BF65F75B4L, 0x016F2E3315A66AFDL, 0xC81FF5A77CA58B92L, 0x2ADABFDEB196CC08L,
                        0x196700B5232D8C11L, 0x4716AB65EC306E2EL, 0x130C517AA603B3EDL, 0x050DDAEBC2E776E4L,
                        0xD0FA1694445CD6A0L, 0x016FEB6936B9C1F7L}
        ));

        vecs.add(new Vec(
                new long[]{0x11BCD96CB3BE0FE2L, 0x2F850F4A8CEB89BEL, 0x3895A599CFAAA1F1L, 0x0C8EDA0235D61429L,
                        0x26434AD67C2CCA2AL, 0x5C95223881686ACFL, 0x4657B82350750B1CL, 0x1DE220506749E1F4L,
                        0x4A4C5FDC75244AA8L, 0x3E60F7F4983AB8BAL, 0x0B84BC0B6CF32383L, 0x199BFFCDF96E6DBEL},
                new long[]{0x466D6598D2798D07L, 0x39AC617E9F04FFA2L, 0x4039C8978890D89EL, 0x4D8D53599771A703L,
                        0x6F6246F24685B207L, 0x6BE62FADC164AFB2L, 0x6C7DCA7FDD77C007L, 0x5A3C728B6D4A426DL,
                        0x16DD238596E0D98FL, 0x74E300D46BC04BEBL, 0x603779567E165807L, 0x4AECB36F92B03EA7L},
                new long[]{0xDE7AA30C459655AEL, 0x154EA594806C8F77L, 0x9280AABBBB8DC058L, 0x7A2DAB946BF2BC46L,
                        0x0CAFEC919C30B869L, 0xABF012BD7AF3CBCEL, 0x2F9F1E7B7B3DE17FL, 0x37C4CB7C0BB2AF87L,
                        0xED4D2E979AE8C326L, 0x5333384AB5C85B80L, 0xFE2AEAAA229B8C22L, 0xF2909C39BB8ED709L,
                        0x4DEFE85D3D644F74L, 0x099F6939185CF2BDL, 0x56962F962616C7E8L, 0x5741D6486FF6DBCEL,
                        0xF3E26CD7193889DFL, 0xAA3E8683D82B4578L, 0x3986A86AE14EEAE4L, 0x11FC2E3CB3820788L,
                        0x4B7D361CA83B2A2CL, 0x9C0659B1E6114CD9L, 0x856F50447D6F7704L, 0x06902B752C11085DL}
        ));

        vecs.add(new Vec(
                new long[]{0x44D0807EE9F7EA34L, 0x6F2C1B13FCCF62B2L, 0x2ED7697937CD752CL, 0x5B8CAF84621ABFC5L,
                        0x11710CBD4BD33242L, 0x045FBDFB7002D8EAL, 0x754A6326196D2AD2L, 0x5F0C30D410BE20D9L,
                        0x44A4C04870C4EBCBL, 0x0D30D68307A8239FL, 0x0BF90E7F0EE41A40L, 0x73334A6F17D24782L,
                        0x4E4A1DF2B9D36C17L},
                new long[]{0x21293A028F3541DFL, 0x60212FFD60D55B9EL, 0x16E1CAA6E779C692L, 0x4974F3B8C40BDF1CL,
                        0x3E9E14835116780BL, 0x2A3567B0ED2F3E12L, 0x59EF5204A8A0C929L, 0x68EEC1B301136358L,
                        0x3299FF6B25D4F09BL, 0x3FB1233C2946449BL, 0x160384F1BF981DAFL, 0x0A59808C1500FB6FL,
                        0x16742171D0307A8DL},
                new long[]{0x2244DF254D4AC76CL, 0x982395A1B40931DCL, 0x529E776E20F00BECL, 0x029AFD51D4574A70L,
                        0x5908A1529C41E3C2L, 0xFEA775C62E9BD0B9L, 0x1135AC655DDD71C8L, 0x0E1601343493C1C1L,
                        0xA7B414606BC2F1C5L, 0xC740526FBD1DE529L, 0xDBD7B1F79AEFC2BBL, 0x72CA5F4143FEDFFAL,
                        0x1D7DE315FD22D9C1L, 0xAC5E759B445AED96L, 0x0F18A3C4F1CDF242L, 0xA803A0A45E180967L,
                        0xF8E30C311289B3EFL, 0x0DB5A93DBFBCEAECL, 0x71380CC34606422EL, 0x4113718B5A9DD1B1L,
                        0x37BDCED7B50B2741L, 0x8E9696BB041AE723L, 0x542A8DBA9D6B91F6L, 0x262FA782307748B2L,
                        0x1DCE92FCAB2D4591L, 0x055E9247A6C3550AL}
        ));

        vecs.add(new Vec(
                new long[]{0x704FC03AC9ED9589L, 0x2062D96074EB6D00L, 0x1FF97C86FAD8F8BDL, 0x2A29535B84ED7A21L,
                        0x49C4DB0824BA6FF4L, 0x358001A5B67BEE39L, 0x4ABD90C35D670154L, 0x20607E75B483784BL,
                        0x623578C8D27CA42DL, 0x1CB24968B87032D2L, 0x2DA9B06D687A4F74L, 0x66FDDB3D44B26B31L,
                        0x2D8DE98D9F71E85EL, 0x39BC8470CA8689DEL},
                new long[]{0x6D752D613815ABFFL, 0x1E8BC456632B99F9L, 0x0A7E5F5B72664A45L, 0x204DE4722358A546L,
                        0x0AB264551FA7F6A1L, 0x5A34AAC5B248BBC1L, 0x52CE387ED879810AL, 0x0729B61C452A8213L,
                        0x130F9AEF51D5CED1L, 0x47F994525677D620L, 0x5B4567C95B900A7FL, 0x1B8E7A7D38DDF661L,
                        0x31B7C6C2EFA00BF1L, 0x1585960569020467L},
                new long[]{0x7BF606A15D727887L, 0x491DD91013E8C78FL, 0xD54E3085DAF0C058L, 0xE29D6AE15FA8A34DL,
                        0x8D447824BC9C7D55L, 0xED3AD41AB276266DL, 0xC439BD07FDD9FAD6L, 0x9E586C4419592EBEL,
                        0x4E4F7D12C9E9894AL, 0x9F0823ADDA146E24L, 0xFB343235AA285FA7L, 0xD6C8A8FE5289711FL,
                        0xFC903042225C7DAEL, 0x697B9D6C90468A5EL, 0xCB203394C4C474EBL, 0xF1CFAD805E4F3966L,
                        0xFCDCABCAD1169DCDL, 0x5B17AC13F7EAA79EL, 0x063CD38927BC60E7L, 0x8C78AA5C4768592AL,
                        0x18BE806DC9F7F7F4L, 0x35C31B21624E1864L, 0x67B96FFF425EB5EDL, 0x2D9E4340CE0ABE67L,
                        0x5BD61B00EFC8223CL, 0xE888BA8F9C2A4FB2L, 0x09BD174FADD111C8L, 0x0358980EC41A13AFL}
        ));


        vecs.add(new Vec(
                new long[]{0x108FD3BE1F201D01L, 0x134FEFC595321C83L, 0x1AF18A3F4D0B5371L, 0x7FEE983A6B66C02BL,
                        0x407DEDB8D8C365B1L, 0x201B81ECA44D5C78L, 0x40796C08F8A5B64FL, 0x486DD4490451FF1FL,
                        0x4D6E26686809075CL, 0x13175B4547B0A9B4L, 0x45B4DE7A26196464L, 0x00128A20F4DE0BA3L,
                        0x3BEF142714E941C0L, 0x3EEE14F3C442B793L, 0x1A9EDF78113F3BAAL},
                new long[]{0x6EE5F07966356394L, 0x2BB09E3A16DA2E6FL, 0x275BDEDD2D945C9FL, 0x70945E74390614B7L,
                        0x4E6087E316192812L, 0x2415D34A83C74315L, 0x3E54AB10C61C024DL, 0x3B8BA898DD1A197FL,
                        0x30CEAA381776EC8AL, 0x5449C5BFDB9B2D2AL, 0x0A512DE183D726ADL, 0x404D924EBAA1A1EBL,
                        0x3BD3A3878129FC33L, 0x75FF7AAA17F54352L, 0x2EF896D283E79C2CL},
                new long[]{0xD6BDA86E057D4794L, 0xA324944457239456L, 0xB685837A556021B8L, 0xF83D3C436586B24FL,
                        0x913AD7C711811B64L, 0xB6535A173B582D53L, 0xC5C5DC9034A862CFL, 0x62709B62B6487A06L,
                        0x844D98F46C774591L, 0x0B6247F5407847C1L, 0x69441C36F7E5DCF2L, 0x6876A9F8119A6C34L,
                        0x9A2DE03561E49947L, 0xE50D81F866E0C7ABL, 0x70FA39C1F772E8EEL, 0x994D87AC82D2007AL,
                        0x0FA6752A347C0F71L, 0x89B04DF6653F3F34L, 0x72AACD339C31FC80L, 0x2EE189C86594EADDL,
                        0xFCB506866714B28FL, 0xCEDF2A1F4758B718L, 0x982131E51D5E6FCFL, 0x3FCDBB511F462736L,
                        0x4E3FBB130C6413F2L, 0x92D43522115DAC6EL, 0x58400F8FC89F85F4L, 0x890449F17C8157F1L,
                        0x3DD41302911FA78BL, 0x03D1A17CEE6F7D45L}
        ));

        vecs.add(new Vec(
                new long[]{0x34B58E8C10C693C0L, 0x56121476897C3A3FL, 0x0E9ACB4FA2360F0CL, 0x1EA147C69E5E42DBL,
                        0x0EEA7003E158BD6DL, 0x55035EA9CC88F97FL, 0x7417BEC552F6902EL, 0x714D1E23FA07804DL,
                        0x02827DB196DD4B06L, 0x1725BC93CF2930AAL, 0x443EE02397F66AB5L, 0x2EA1999DCFCAB8B5L,
                        0x62183B815AEB8529L, 0x4B119E59EA6EF38EL, 0x649053B50E6F54D4L, 0x727C5FA76C775A53L},
                new long[]{0x610DAA42C816371DL, 0x326A6B4E08007173L, 0x5AA166CC01139614L, 0x5338CFABC2042186L,
                        0x09DAA299DC843406L, 0x0B6181F71D49660CL, 0x4BB0BB3D85787091L, 0x696FEE13101FD21FL,
                        0x46B221F0E152806DL, 0x653D263751541CF6L, 0x0EC8C0340FDF24CAL, 0x0D6BDB70B6BE264EL,
                        0x01C6DFB007D4EEEFL, 0x457D3DE9DDE0C1C2L, 0x5E404C7DC33A1EE8L, 0x126BE2D70827FC67L},
                new long[]{0xFAF22F8B67BE3EC0L, 0xE8E79F84232F199CL, 0x3D091735523C171CL, 0x4C0478AFC1C9FA13L,
                        0x266D2F28284D8C5CL, 0x71E04CCE1830EA70L, 0xBF38614A7B6DD56BL, 0x7968851DDB9C79DCL,
                        0xF0FF1B8F35222FE1L, 0x4EF3901D9C1E71D0L, 0x079F45899979093BL, 0x180B1A523912A05DL,
                        0x6C5F79F6FFA1E1C1L, 0x9E6791FF48D9A650L, 0xB8387464955CD5F9L, 0x7B29963CBD78531AL,
                        0x618A9533B8D271FFL, 0xB8E4886DD430C462L, 0x5E2DDB37E65F9337L, 0x0131FAECBFA2C5BCL,
                        0x8BF346C4F76050DEL, 0x4CAD59B8BB31F00FL, 0xE6D217C01A2E7983L, 0x962DCF8D7FE9FF99L,
                        0x208559084F80CD69L, 0x81C7BDDD558E40CAL, 0x073A86DA0769C9BCL, 0x5DCE8CDD66696FD0L,
                        0x54E7501ECAA96AD9L, 0xF873F7EA3EE947EAL, 0x4AEC7E0AD54AE3C1L, 0x07D2C396A99E9393L}
        ));

    }


    @Test
    public void testMul()
    {

        for (int i = 0; i < vecs.size(); i++)
        {
            Vec vector = vecs.get(i);

            long[] z = new long[vector.expected.length];
            Mul.multiplyAcc(vector.x, 0, vector.y, 0, z);

            for (int t = 0; t < z.length; t++)
            {
                Assert.assertEquals("Vector: " + i + " Result: " + t, vector.expected[t], z[t]);
            }

        }

    }


    private static class Vec
    {
        public final long[] x;
        public final long[] y;
        public final long[] expected;

        private Vec(long[] x, long[] y, long[] expected)
        {
            this.x = x;
            this.y = y;
            this.expected = expected;
        }
    }
}
