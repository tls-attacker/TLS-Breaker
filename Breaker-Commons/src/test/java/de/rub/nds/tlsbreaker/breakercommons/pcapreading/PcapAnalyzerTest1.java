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

/*
 * TESTING THE PCAP WHICH HAS RSA KEY EXCHANGE SESSIONS. EXPECTED RESULT : 1 PMS
 * Failing to pass this test will indicate that the pcap session extraction code block is broken.
 */

public class PcapAnalyzerTest1 {

    private String PmsStoredValues;
    private File FileLocation;

    public PcapAnalyzerTest1() {
        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "Sample1.pcapng" + File.separator);
        PmsStoredValues =
            "60ca0832ac2eb6130b3d695e4e1308f6241b5cbd7e57d3530ff311ebffd47910d67d7f835a6ce8ad859f51cd0f07e794acd6c133f35f67e9b7e18b3f3c67c793d1bb9fd865d661e32317f3f1e95e480998218b9bb09ff90bc2482c32c6e2e4905545980d35b565fecdfd06b1861fb641d151b823abc11e917c5f73d2daeb7231";

    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Test
    public void testgetPreMasterSecret() {

        PcapAnalyzer sample = new PcapAnalyzer(FileLocation.getPath());

        List<PcapSession> sessions = sample.getAllSessions();
        byte[] pms = sessions.get(0).getPreMasterSecret();// sample.getPreMasterSecret(sessions.get(0).getClientKeyExchangeMessage());

        char[] pms_after_convert = Hex.encodeHex(pms);

        boolean validation_result = PmsStoredValues.equals(new String(pms_after_convert));
        assert (validation_result);

    }

}