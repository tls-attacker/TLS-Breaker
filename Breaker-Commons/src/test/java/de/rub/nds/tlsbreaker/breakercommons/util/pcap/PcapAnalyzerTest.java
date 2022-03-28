/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import org.apache.commons.codec.binary.Hex;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.*;

public class PcapAnalyzerTest {

    private File FileLocation;
    // private int i = 0 ;

    public PcapAnalyzerTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    public List<PcapSession> fetchsessions(File pcapFileLocation) {
        PcapAnalyzer sample = new PcapAnalyzer(pcapFileLocation.getPath());
        return sample.getAllSessions();
    }

    public void extra_details(List<PcapSession> sessions) {
//        System.out.println("#########################   SESSION SIZE #############################");
//        System.out.println(sessions.size());
//        System.out.println("#########################   FILE LOCATION #############################");
//        System.out.println(FileLocation);
//        System.out.println("#########################   Extracted ENC PMS Value #############################");
//        System.out.println(pms_after_convert);
    }

    /*
     * TRYING TO EXTRACT ENC PMS from Cipher Suite: TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 (0x00ac) WHICH HAS 4 PARAMETERS
     * IN CLIENT KEY EXCHANGE ---> RSA PSK CLIENT PARAMS SECTION [IDENTITY LENGTH, IDENTITY,ENCRYPTED PREMASTER LENGTH,
     * ENCRYPTED PREMASTER] WHERE HAS OTHER PCAP CONTAINS ONLY [ENCRYPTED PREMASTER LENGTH, ENCRYPTED PREMASTER]
     */
    @Test
    public void testPSKCipherEncPMSExtract() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "2nd_TLS_RSA_PSK_AES.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);

            try {

                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * TRYING TO EXTRACT PUBLIC KEY from THE PCAP WITH Cipher Suite: TLS_DH_RSA_WITH_DES_CBC_SHA (0x000f)
     */
    @Test
    public void testDHRSAEncPMSExtract() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "DH_RSA.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "63865c3198da9c1eb3836e5b4f395bf95f3897c5035aab70ed300f3fdc904fc66aa7b9a1d023c34f0053432b9871d5aff2d7f4231ce186bda754604b2e664c5762ef81f557506bb35d16522864d67c2c1b014ba44fb2b93155a167ba75c1bed38084e2025db424a39f46e09a576ce1c6b6e938cf68e2277597e0890b00c9626e0260fdfc08df0950d9302402c04afd3dea08ccc69c8877562a5d60d21caab20893a9977b15326a96a3f4e641e5ab77c69309e30d0f7cdb568e7e1d179c28679185edf566aff4973ef167f04fb769695769e503236361042a856dc2988e5b64a2dfd048e28aebb6ad153b1512cb4a5c03a8a8d949248fb74882896ebf430d299ebeff912a3558329cfbf553b5f1fd3d3da7138eb293a4929035da2305913645eb68305d9e1ea49f33af352f02d38133d4873766b07d287dd0221f4a8dd40ca5661e99edb67500e3b92e82bc2666ec9c61071427371817c0253468558df0e808660a6c4a9fef4e1e81c6288b6e6f3d48ca2c81e3c8155cfe89a1d9d3566ef2ebfc");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
//            System.out.println("#########################   Extracted ENC PMS Value #############################");
//            System.out.println(pms_after_convert);
            try {
//                System.out.println(i);
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /* CHECKING PCAP WHICH CONTAINS ENC PMS OF SIZE 1 BYTE */
    @Test
    public void testEncPMSWithSmallSizeExtract() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "TLS_SRP_SHA_RSA_DIFF.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList("20");
        List<PcapSession> sessions = fetchsessions(FileLocation);
        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);

            try {
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));
            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }
        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * CHECKING PCAP WHICH CONTAINS ENC PMS BUT THE VALUE IS NOT DISPLAYED IN WIRESHARK Cipher
     * Suite:TLS_RSA_WITH_ARIA_128_CBC_SHA256 (0xc03c)
     */
    @Test
    public void isEncPMSExtractedWhichIsNotDisplayedInWireshark() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "2nd_TLS_RSA_WITH_ARIA.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025");
        List<PcapSession> sessions = fetchsessions(FileLocation);
        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);

            try {
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));
            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }
        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * TRYING TO EXTRACT PUBLIC KEY from THE PCAP WITH Cipher Suite: TLS_ECDH_RSA_WITH_NULL_SHA (0x000f)
     */
    @Test
    public void testECDHPublicKeyExtract() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "TLS_ECDH_RSA_WITH_NULL_SHA.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);

            try {

                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(0), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * CHECKING SSLV3 PCAP FOR ENC PRE MASTER SECRET EXTRACTION BELOW FILE HAS 6 SESSIONS ALL BELONG TO SSLV3 AND HAS 3
     * DIFFERENT ENCRYPED PMS VALUES
     */
    @Test
    public void testSSLV3EncPcap() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "SSLV3_pcap.pcap" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "9c5dfc0170b128ec206bf3a1d3ddbb64d6145801e71a4c1738c6b78530dbfc16130460db7ffb42a903efa1859fd98584001ac4ac36f9daf869a5878321037382f20b05dfdea1fad919c867158164a04a5553c2fb676e7755c50f850b0323faf94a4856b0c9099ee161ba8461dce8bcf804f23a6fc61a46f9ce788b99e74a82b1",
            "00b46a85398faaa065a43002f0d552fb3f5d5869e55aef98247765009d2e6ed8bdd373f335f3b6634bf882e1c289d58984f6a400941e31fb4a6bf1111c014bdf74843e07a274f7a326c02e24180c67bb3626b38ccc04fc1084332c83e8892d999b30032c4c7a9c2afbe6931d9b572d59503af1491f85287d8f975ed7ec6d4280",
            "32f9b5f3f2bfbda93df5a8d49dc0fe10277e8f8c922b6d1b092f4aeb1aaed15935cc54802e48416fae44817c05ca52fd6e23b2e35ff62dedf6beb58cd1260e5a4c9c155dbcd4a61d4a2a249ce703d6cf444707df1cffe0afac7496e25efc401c0906eb0ee7b9eb93d09fe99dc82e7775274f0e4dd5cea6d34063fd9cf13a4598");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        Assert.assertEquals("Expected number of session", sessions.size(), 6);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);

            try {
                boolean validation_result = PmsStoredValues.contains(new String(pms_after_convert));
                if (!validation_result) {
                    System.out.println(pms_after_convert);
                    Assert.fail("EXTRACTED ABOVE ENC PMS DATA FROM THE FILE WHICH IS UNKNOWN");
                }

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * CHECKING A PCAP FILE WHICH HAS MORE THAN 40 SESSIONS
     */
    @Test
    public void testBigFileForAllSessionExtraction() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "Sample5.pcapng" + File.separator);

        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        Assert.assertTrue("Error in reading correct number of sessions",
            (sessions.size() >= 48 && sessions.size() < 52));

    }

    /*
     * CHECKING A PCAP FILE WHICH USES PSK HAS KEY EXCHANGE
     */
    @Test
    public void testPSKCipherFile() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "TLS_PSK_WITH_ARIA_128_CBC_SHA256.pcapng" + File.separator);

        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        Assert.assertEquals("NUMBER OF SESSION PRESENT IN THE FILE", sessions.size(), 4);

    }

    /*
     * CHECKING A PCAP FILE WHICH CONTAINS ALL THERE VERSIONS(SSLV3,TLS1.0,TLS1.1,TLS1.2) IN A SINGLE PCAP FILE
     */
    @Test
    public void testAllThreeVersionRead() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "TLS_RSA_WITH_AES_128_CCM_8.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "964c569dc5a76281f5cc3e06943790124e9657e909725715596b7dae61af0b97897e568baa1cc140c3345e3027216a5916289c8b83b0e67541fb62e84839bdde07769507706c37680f39e6fd484a241607a9a7441af1dbf873bf7dc122da9bcdd1efdea48dfc3b67cd0e6bc40c9981d2775cbc8f559373140738b930e4c98d928a562d283556dc7ef8666fadaf1a721e8dfb36c40f390bb364d55263bb5b026d3809c5ad5be24d89cbf9e5df10e5b1f37758168cb103f2f86982c0c5dae931c8b5129db8ee83e712e8efd7a02d1a1c847463fc1ebe99891b8cd43a5e2cb7b6b9d633eab43e66267600eecfca9d0675bdb2056425cbe8013abb7e53dd5a7fd3cb",
            "04136b37105afb806709431c6aec699733b7d49d1387183a639a85e62796e608feb2b4f4ccf5946deb1cb21c32a02a3d153c9a8d14a5b271b4c7e26b11987221c61a2ea5bc1afd27d334876b496da4d17a0095e4aed7ab0d8f4ce233d918f6c09d6e4c1cf32de73c70524ebafa78ab893423c6402c84d255a21effc0b3afb7b3549a0862c0a2f31a49f533466316c0d666b03ef08da58f4b232fccc5695840ad6485fe98c819a92ab545bc1c10ecb3592fafe4b24f580307b4d5791fb54d4392da2929be3361748ddba340de42abd1b161d118901d6895fd39d4f92e58b81a46b84409b958e0200d8e7b7db53097dbb15f88ebca3e6300dd116459f888ca877b",
            "66eedcf297f82122d280c190a754556c97652307116ffed16b17b585df51c93190c25f03fb9d85cd0d04beee2517d4641bf7733f5d50fe0dbf1f33fd53371eb933e32a645caab6c17b9f28aecc13b81226146272571ca6c9cf9faa12d2cdf42dbec19ae6aff7b7ca99144848fb8c44fe2172ac11bdd1f05c49bd86d4d9e25201cec51d565cdf6958a0d1941de8e692e01effd10c9ebe538fdace68145c5fa57a0529a57612ec76cf5c08f828148d833e68c31ffa0477fdc748638feecbd8ab55dfa2923ea3132338984bb3e543c5c515b4c961cf6e0f1a4305e46523d8c6121fa9e964327e83e87290f001089e965dc9395da0a9f4a844a673ba0e473caab590",
            "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025");

        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        Assert.assertEquals("NUMBER OF SESSION PRESENT IN THE FILE", sessions.size(), 4);
        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);

            try {
                boolean validation_result = PmsStoredValues.contains(new String(pms_after_convert));
                if (!validation_result) {
                    System.out.println(pms_after_convert);
                    Assert.fail("EXTRACTED ABOVE ENC PMS DATA FROM THE FILE WHICH IS UNKNOWN");
                }

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());

    }

    /*
     * CHECKING A PCAP FILE WHICH CONTAINS PUBLIC KEY AND ENC PMS DATA
     */
    @Test
    public void testMixedPcapRead() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "Mix_file.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "63865c3198da9c1eb3836e5b4f395bf95f3897c5035aab70ed300f3fdc904fc66aa7b9a1d023c34f0053432b9871d5aff2d7f4231ce186bda754604b2e664c5762ef81f557506bb35d16522864d67c2c1b014ba44fb2b93155a167ba75c1bed38084e2025db424a39f46e09a576ce1c6b6e938cf68e2277597e0890b00c9626e0260fdfc08df0950d9302402c04afd3dea08ccc69c8877562a5d60d21caab20893a9977b15326a96a3f4e641e5ab77c69309e30d0f7cdb568e7e1d179c28679185edf566aff4973ef167f04fb769695769e503236361042a856dc2988e5b64a2dfd048e28aebb6ad153b1512cb4a5c03a8a8d949248fb74882896ebf430d299ebeff912a3558329cfbf553b5f1fd3d3da7138eb293a4929035da2305913645eb68305d9e1ea49f33af352f02d38133d4873766b07d287dd0221f4a8dd40ca5661e99edb67500e3b92e82bc2666ec9c61071427371817c0253468558df0e808660a6c4a9fef4e1e81c6288b6e6f3d48ca2c81e3c8155cfe89a1d9d3566ef2ebfc",
            "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025");

        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);

            try {

                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(i), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());

    }

    // ############################ NOT IMPLEMENTED ########################################

    /*
     * TRYING TO EXTRACT PUBLIC KEY from THE PCAP WITH Cipher Suite: TLS_ECDHE_RSA_WITH_NULL_SHA (0x000f)
     *
     */
    // @Test
    public void testECDHEPublicKeyExtract() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   Extracted ENC PMS Value #############################");
            System.out.println(pms_after_convert);
            try {
                System.out.println(i);
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(0), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    /*
     * Cipher Suite: TLS_RSA_PSK_WITH_AES_128_CBC_SHA EXTRACTING ENC PMS VALUE FROM THE SESSIONS WHERE THE WHOLE PCAP
     * FILE CONTAIN 1 ENC PMS VALUE WITH ONE SESSION BUT IT HAS FEW TLS DATA EXCHANGE IN BETWEEN SOME OTHER HANDSHAKE
     */

    // @Test
    public void testEncPMSExtract() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "psk_captured.pcapng" + File.separator);

        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "8ed4198be5099c96ac923d54300717dc24814cc2aa0405556084f2d6ce4e48935db7461a74f319768686182afdbbc819c0c222643f1adc492f889f3627bea1affb523a1574eb778cbc985808074a9b8fe7f09705b1fbb9159e7a64e26c99859a69c5a9a36c02961ff1ba68363ade466ba1ed4413d10767d960dc577fd88e20df1fbacc46694d2b36c8683f96703561d779a1d329bb2c51b804097a45602eebdef79f8ce17aa1867b6f10a83b609a9efe0eec0d169d1b827b1990583bd97dcc390e5356fb0f6c27b784656716320eae45ef4cebb99d030a7e10053e96f58c8128a6aa19ceb7de70c249485ba9fd75ee91637485c99bc5a895900e594950641025");
        List<PcapSession> sessions = fetchsessions(FileLocation);
        extra_details(sessions);
        Assert.assertEquals("NUMBER OF SESSION PRESENT IN THE FILE", sessions.size(), 1);

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
     * TRYING TO EXTRACT PUBLIC KEY from THE PCAP WITH Cipher Suite: TLS_DHE_RSA_WITH_NULL_SHA (0x000f)
     */
    // @Test
    public void testDHEPublicKeyExtract() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256.pcapng" + File.separator);
        int i = 0;
        List<String> PmsStoredValues = Arrays.asList(
            "045ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032");
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);

        for (i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();
            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   Extracted ENC PMS Value #############################");
            System.out.println(pms_after_convert);
            try {
                System.out.println(i);
                Assert.assertEquals("Expected PMS VALUES", PmsStoredValues.get(0), String.valueOf(pms_after_convert));

            } catch (ArrayIndexOutOfBoundsException e) {
                Assert.fail("Trying to Extract More Enc PMS values which are not present in the PCAP File");
            }

        }
        Assert.assertTrue("Required Number of ENC PMS not extracted", i >= PmsStoredValues.size());
    }

    // #################################### NOT IMPLEMENTED ##################################
    /*
     * CHECKING PCAP WITH ONE PUBLIC KEY DATA PRESENT AND THE SOURCE AND DESTINATION CONTAINS CHARACTERS Destination
     * address: Buffalo_0e:33:3c Source address: IntelCor_d2:5e:a8
     */
    // @Test
    public void testPcapWithNoEncPMSData() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "psksample.pcap" + File.separator);
        List<PcapSession> sessions = fetchsessions(FileLocation);

        extra_details(sessions);
        Assert.assertEquals("PCAP contains 1 CKE", 1, sessions.size());
    }
}