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
import static org.junit.Assert.*;

public class PcapAnalyzerTest5 {

    private File FileLocation;
    private int ClientKeyExchangeCount = 48;
    List<String> PmsStoredValues = Arrays.asList(
        "10941c855a14140cc84657f9fb1f23e37de4ac009b9334f4050bdd9488285d71faf3246f9af6001c1e25c7a9b2ee91d2e9ebda8b4960f3441c2aceca525221e899e8aa94b90b592130111cb94400a05c385da1fa0782e112cae09efe90220fe6d12d0c43b13d04787163dc62573fac53a7d85b6998922d0d99b0c038c8e83cd99dc5fafd686ff29c4796ae610c37a953c3f3898b5b866d69f04624af594e2a1ae2638f361538117465c4d5caac4dc0061011a7924f333363c1cafce5a944e29fbfbe62658e9292712313316bbe8829551186be5a9f94290b831b15c26753f22888ed5d93c4b09199f3de85fcf3e54951fda59a4477bf2e5e9abf338cce1fd92b",
        "ab74132984c60dd25e9dcfc94011e3800a84950e3f846cc23d22c5ea47897e8558a9e42b786955071ed744aaa187e8f6d9d9a7077302fbc107bf48e66ab43a46f05d832617f1d0825a6c1d0ee8b6ea31ba4ea41579d8a6a644e2722f31d2f0262a38788069401db92b733b2d085bd905e8280a4879ed0e3d5f6c3e6d3f37660c33cf59a2ef5e77cc9e999d86477176ae60133002f5b19d8094c8dd59449d9454c253d708acb3515b6e62d0c63cfa1aac4a7503d9b7adb2f18a16c3e1b41ad556bafeebbee1b67357d9c4b252939f6227b61945ef9c216515bc9b2a6f3fe1e8e9500cc99c80a62d3e24cc81bfb808b1445dbf658ef84b468f8d283cdb44370496");

    public PcapAnalyzerTest5() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
            + "pcap_files" + File.separator + "Sample5.pcapng" + File.separator);

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

        for (int i = 0; i < sessions.size(); i++) {
            byte[] pms = sample.getPreMasterSecret(sessions.get(i).getClientKeyExchangeMessage());

            char[] pms_after_convert = Hex.encodeHex(pms);

            if (i < 2) {
                boolean validation_result = PmsStoredValues.contains(new String(pms_after_convert));
                assert (validation_result);
            }

        }
        System.out.println("#########################   LIST OF SESSION 5 #############################");
        System.out.println(sessions.size());
        assertEquals(ClientKeyExchangeCount, sessions.size());
    }

}