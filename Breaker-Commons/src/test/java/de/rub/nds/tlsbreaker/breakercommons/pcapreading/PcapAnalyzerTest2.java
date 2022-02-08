/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.pcapreading;

import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.apache.commons.codec.binary.Hex;

import java.io.File;
import java.util.List;
import java.util.Arrays;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class PcapAnalyzerTest2 {

    private File FileLocation;
    List<String> PmsStoredValues = Arrays.asList(
        "63f094976db528b0fac4a130ffea435a098a036f1697700b16e2f795e86b4f5ff614175235e5e8cfc6d97253506a39c7069ac315d5f005ac6f9ee9274f2f5909deb11c567698565b485d63409104e6e3b0ac608355fa5fd91f925614b243bc647f1a7c54322cd16072a574d1fb585d7db84516e5d9e5b80d8870ffccea2c7bf986c99d70c3c5e8da98c07da96587a86711ca2604f2679e81e9c1513a346aecb288b687cc80f62e70991899de704a5570d609bd70edcdeb7e66155274db2df1002813a1927d2c244c68415b215aa257a0e99139ecfa38cdbaa28a026dcbdfdd0b4df3d0a6328b25cf750dc98d665c2b18e6f16a61c5e1f097e6395faa69c61a6a");

    public PcapAnalyzerTest2() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "Sample2.pcapng" + File.separator);

    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    // @Test
    public void testgetPreMasterSecret() {

        PcapAnalyzer sample = new PcapAnalyzer(FileLocation.getPath());

        List<PcapSession> sessions = sample.getAllSessions();

        for (int i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();// sample.getPreMasterSecret(sessions.get(i).getClientKeyExchangeMessage());

            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   PCAPANALYZERTEST 2 #############################");
            System.out.println(pms_after_convert);

            boolean validation_result = PmsStoredValues.contains(new String(pms_after_convert));
            assert (validation_result);
        }
    }

//        System.out.println("#########################   LIST OF SESSION 2 #############################");
//        System.out.println(Arrays.toString(sessions.toArray()));
//
//        System.out.println("#########################   SESSION SIZE #############################");
//        System.out.println(sessions.size());
//        char[] pms_after_convert = null;
//        for (int i = 0; i < sessions.size(); i++) {
//            byte[] pms = sample.getPreMasterSecret(sessions.get(i).getClientKeyExchangeMessage());
//
//            pms_after_convert = Hex.encodeHex(pms);
//            System.out.println("#########################   PCAPANALYZERTEST 2 #############################");
//            System.out.println(pms_after_convert);
//        }
//
//        boolean validation_result = PmsStoredValues.contains(new String(pms_after_convert));
//        assert (validation_result);
    // }

}