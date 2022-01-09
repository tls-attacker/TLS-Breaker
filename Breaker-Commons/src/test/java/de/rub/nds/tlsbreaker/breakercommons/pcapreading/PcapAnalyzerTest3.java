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
import java.util.List;
import java.util.Arrays;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

public class PcapAnalyzerTest3 {

    private String FileLocation;
    List<String> PmsStoredValues = Arrays.asList(
        "707eb01ca5981df78cbe2a44f5c667039d2c35d77db180c89857c534c8ad8b775c6427403bd863e50e9218c10c12e4e22b244089bd6fe0ae19806c20f9ba246a346b147e9351ccbe4b93048cef2e1af6f5a27b02fdf8ddd50cd9de6eecee8378bd45de724f06ffa22fea6c0ff53cbc10321f0ade472f7a689735f80ad432ff20",
        "20ebbf46d49c0dc18b4fc26dce50ce5a6c5ce7ecc79fa236546476da91571625d10b5e9e14a5ffdbac37e1bdf8461d13811dfa72ebb65ce1d754c80307ba2fd492435504b341e7cce1ce724e611ef297372dc9fa7ff7178d361f8bcdbe485292d1bb7847756c54c2e28c8780838b9d10d1b9c8f8445411ff539507d3bb271a2a",
        "60514d9424f0c47db8e45a779cd4ef5f9008560199be8266332d1e365e8782f9b0c3bc18d7c28320ebce0fd84226a401f8754cabb0fc6ae4a664d345176f80d06deb9f31e69e0fbacb7c84eed93fc0ff48b3e7e97092028f9e99a79696854f73d0aa43108dcd9d941275274c1417ef52496eebab76075ff443bd3ce44bab1dff");

    public PcapAnalyzerTest3() {
        FileLocation = "src\\test\\resources\\pcap_files\\Sample3.pcap";
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

        for (int i = 0; i < sessions.size(); i++) {
            byte[] pms = sample.getPreMasterSecret(sessions.get(i).getClientKeyExchangeMessage());

            char[] pms_after_convert = Hex.encodeHex(pms);
            System.out.println("#########################   PCAPANALYZERTEST 3 #############################");
            System.out.println(pms_after_convert);

            boolean validation_result = PmsStoredValues.contains(new String(pms_after_convert));
            assert (validation_result);
        }

    }

}