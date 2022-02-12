package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import junit.framework.TestCase;
import org.apache.commons.codec.binary.Hex;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class PcapAnalyzerTest {


    private String FileLocation, PmsStoredValues;
    // private int i = 0 ;

    public PcapAnalyzerTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    public List<PcapSession> fetchsessions(String pcapFileLocation) {
        PcapAnalyzer sample = new PcapAnalyzer(pcapFileLocation);
        return sample.getAllSessions();
    }

    public void extra_details(List<PcapSession> sessions) {
        System.out.println("#########################   SESSION SIZE #############################");
        System.out.println(sessions.size());
        System.out.println("#########################   FILE LOCATION #############################");
        System.out.println(FileLocation);
    }

    /* Cipher Suite: TLS_RSA_PSK_WITH_AES_128_CBC_SHA */

    @Test
    public void testEncPMSExtract() {
        FileLocation = "src\\test\\resources\\pcap_files\\psk_captured.pcapng";
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
                "60ca0832ac2eb6130b3d695e4e1308f6241b5cbd7e57d3530ff311ebffd47910d67d7f835a6ce8ad859f51cd0f07e794acd6c133f35f67e9b7e18b3f3c67c793d1bb9fd865d661e32317f3f1e95e480998218b9bb09ff90bc2482c32c6e2e4905545980d35b565fecdfd06b1861fb641d151b823abc11e917c5f73d2daeb7231");
        List<PcapSession> sessions = fetchsessions(FileLocation);
        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   Extracted ENC PMS Value #############################");
            System.out.println(pms_after_convert);
            try {
                System.out.println(i);
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * TRYING TO EXTRACT ENC PMS from Cipher Suite: TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (0x00ac) WHICH HAS 4 PARAMETERS
     * IN CLIENT KEY EXCHANGE ---> RSA PSK CLIENT PARAMS SECTION
     */
    @Test
    public void testPSKCipherEncPMSExtract() {
        FileLocation = "src\\test\\resources\\pcap_files\\2nd_TLS_RSA_PSK_AES.pcapng";
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
                "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   Extracted ENC PMS Value #############################");
            System.out.println(pms_after_convert);
            try {
                System.out.println(i);
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * TRYING TO EXTRACT ENC PMS from Cipher Suite: TLS_DH_RSA_WITH_DES_CBC_SHA (0x000f) WHICH HAS PUBLIC KEY
     */
    @Test
    public void testDHRSAEncPMSExtract() {
        FileLocation = "src\\test\\resources\\pcap_files\\DH_RSA.pcapng";
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
                "63865c3198da9c1eb3836e5b4f395bf95f3897c5035aab70ed300f3fdc904fc66aa7b9a1d023c34f0053432b9871d5aff2d7f4231ce186bda754604b2e664c5762ef81f557506bb35d16522864d67c2c1b014ba44fb2b93155a167ba75c1bed38084e2025db424a39f46e09a576ce1c6b6e938cf68e2277597e0890b00c9626e0260fdfc08df0950d9302402c04afd3dea08ccc69c8877562a5d60d21caab20893a9977b15326a96a3f4e641e5ab77c69309e30d0f7cdb568e7e1d179c28679185edf566aff4973ef167f04fb769695769e503236361042a856dc2988e5b64a2dfd048e28aebb6ad153b1512cb4a5c03a8a8d949248fb74882896ebf430d299ebeff912a3558329cfbf553b5f1fd3d3da7138eb293a4929035da2305913645eb68305d9e1ea49f33af352f02d38133d4873766b07d287dd0221f4a8dd40ca5661e99edb67500e3b92e82bc2666ec9c61071427371817c0253468558df0e808660a6c4a9fef4e1e81c6288b6e6f3d48ca2c81e3c8155cfe89a1d9d3566ef2ebfc");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   Extracted ENC PMS Value #############################");
            System.out.println(pms_after_convert);
            try {
                System.out.println(i);
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /* CHECKING PCAP WITH NO ENC PMS DATA PRESENT IN IT and the SOURCE AND DESTINATION CONTAINS CHARACTERS */
    @Test
    public void testPcapWithNoEncPMSData() {
        FileLocation = "src\\test\\resources\\pcap_files\\psksample.pcap";
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);
        Assert.assertEquals("PCAP contains no CKE", 0, sessions.size());
    }

    /* CHECKING PCAP WHICH CONTAINS ENC PMS OF SIZE 1 BYTE */
    @Test
    public void testEncPMSWithSmallSizeExtract() {
        FileLocation = "src\\test\\resources\\pcap_files\\TLS_SRP_SHA_RSA_DIFF.pcapng";
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList("20");
        List<PcapSession> sessions = fetchsessions(FileLocation);
        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   Extracted ENC PMS Value #############################");
            System.out.println(pms_after_convert);
            try {
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));
            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }
        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * CHECKING PCAP WHICH CONTAINS ENC PMS BUT THE VALUE IS NOT DISPLAYED IN WIRESHARK Cipher Suite:
     * TLS_RSA_WITH_ARIA_128_CBC_SHA256 (0xc03c)
     */
    @Test
    public void isEncPMSExtractedWhichIsNotDisplayedInWireshark() {
        FileLocation = "src\\test\\resources\\pcap_files\\2nd_TLS_RSA_WITH_ARIA.pcapng";
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
                "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025");
        List<PcapSession> sessions = fetchsessions(FileLocation);
        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   Extracted ENC PMS Value #############################");
            System.out.println(pms_after_convert);
            try {
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));
            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }
        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

}