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
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class PcapAnalyzerTest4 {

    private File FileLocation;
    public String PmsStoredValues =
        "72ed66df9070c98033961401a194357f95a54d1bcafb51c25717afa960d4517b19299adb3c22f2cec10f9f9eb7475b6e738790d088eea878317f5e9c0d29e441c820623be9dda8a4b5e83fe7b07fa70268b1306c1041d80d13ac7484345376149e590e9cdabf27a6076ce4614c01f7b732c19c2775ac159bc58ff94fc36a8b4a";

    public PcapAnalyzerTest4() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "Sample4.pcap" + File.separator);

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

        System.out.println("#########################   SESSION SIZE #############################");
        System.out.println(sessions.size());

        for (int i = 0; i < sessions.size(); i++) {
            byte[] pms = sessions.get(i).getPreMasterSecret();// sample.getPreMasterSecret(sessions.get(i).getClientKeyExchangeMessage());

            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   PCAPANALYZERTEST 4 #############################");
            System.out.println(pms_after_convert);

            boolean validation_result = PmsStoredValues.contains(new String(pms_after_convert));
            assert (validation_result);
        }

    }

}