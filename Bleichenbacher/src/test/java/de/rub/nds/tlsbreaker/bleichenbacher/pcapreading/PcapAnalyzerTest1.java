/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.pcapreading;

import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.apache.commons.codec.binary.Hex;
import java.util.List;
import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class PcapAnalyzerTest1 {

    private String FileLocation, PmsStoredValues;

    public PcapAnalyzerTest1() {
        FileLocation = "src\\test\\resources\\pcap_files\\Sample1.pcapng";
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
        PcapAnalyzer sample = new PcapAnalyzer(FileLocation);

        List<PcapSession> sessions = sample.getAllSessions();
        byte[] pms = sample.getPreMasterSecret(sessions.get(0).getClientKeyExchangeMessage());

        char[] pms_after_convert = Hex.encodeHex(pms);
        System.out.println("#########################   PCAPANALYZERTEST 1 #############################");
        System.out.println(pms_after_convert);

        boolean validation_result = PmsStoredValues.equals(new String(pms_after_convert));
        assert (validation_result);

    }

}