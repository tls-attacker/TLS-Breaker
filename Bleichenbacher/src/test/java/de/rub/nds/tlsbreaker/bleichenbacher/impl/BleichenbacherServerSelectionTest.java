/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class BleichenbacherServerSelectionTest {

    private List<PcapSession> fetchSessions(String pcapFilename) {
        PcapAnalyzer sample = new PcapAnalyzer("src/test/resources/pcap_files/" + pcapFilename);
        return sample.getAllSessions();
    }

    /**
     * BLEICHENBACHER SERVER TEST TESTING THE PCAP WHICH USES DIFFIE HELLMAN HAS KEY EXCHANGE EXPECTED OUTPUT : 0
     * SERVERS SINCE BLEICHENBACHER WON'T WORK ON DIFFIE HELLMAN KEY EXCHANGE
     */
    @Test
    public void testIsServerDisplayedForDh() {
        List<PcapSession> sessions = fetchSessions("DH_RSA.pcapng");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(0, uniqueServers.size(), "Expected count of server displayed for user");
    }

    /**
     * BLEICHENBACHER SERVER TEST TESTING THE PCAP WHICH USES RSA KEY EXCHANGE EXPECTED OUTPUT : 1 SERVERS
     * (127.0.0.1:4433)
     *
     */
    @Test
    public void testIsServerDisplayedForRsa() {
        List<PcapSession> sessions = fetchSessions("2nd_TLS_RSA_PSK_AES.pcapng");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(1, uniqueServers.size(), "Expected count of server displayed for user");
        assertEquals("127.0.0.1:4433", uniqueServers.get(0), "Expected Destination server");

    }

    /**
     * BLEICHENBACHER SERVER TEST TESTING THE PCAP WHICH USES RSA HAS KEY EXCHANGE WITH SSLV3 PROTOCOL EXPECTED OUTPUT :
     * 4 SERVERS.
     */
    @Test
    public void testUniqueSslV3Pcap() {
        List<String> HostAddress =
            Arrays.asList("207.46.113.78:5443", "65.54.186.19:5443", "65.54.186.19:443", "207.46.113.78:443");
        List<PcapSession> sessions = fetchSessions("SSLV3_pcap.pcap");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(4, uniqueServers.size(), "Expected count of server displayed for user");
        for (int i = 0; i < uniqueServers.size(); i++) {
            assertEquals(HostAddress.get(i), uniqueServers.get(i), "Expected Destination server");
        }

    }

    /**
     * BLEICHENBACHER SERVER TEST TESTING THE PCAP WHICH USES RSA KEY EXCHANGE EXPECTED OUTPUT : 1 SERVERS
     * (127.0.0.1:4433)
     */
    @Test
    public void testPcapWithExtraTlsDataInSessions() {
        List<PcapSession> sessions = fetchSessions("psk_captured.pcapng");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(1, uniqueServers.size(), "Expected count of server displayed for user");
        assertEquals("127.0.0.1:4433", uniqueServers.get(0), "Expected Destination server");

    }

    /**
     * BLEICHENBACHER SERVER TEST TESTING THE PCAP WHICH USES RSA KEY EXCHANGE EXPECTED OUTPUT : 10 SERVERS
     */
    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testBigPcapWithMultipleServers() {
        List<String> HostAddress = new ArrayList<String>(Arrays.asList("204.9.163.181:443", "65.54.186.19:5443",
            "65.54.186.19:443", "72.14.213.120:443", "72.14.213.147:443", "72.14.213.132:443", "207.46.113.78:443",
            "184.85.226.161:443", "67.215.65.132:443", "207.46.113.78:5443"));

        List<PcapSession> sessions = fetchSessions("Sample4.pcap");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(10, uniqueServers.size(), "Expected count of server displayed for user");
        for (String uniqueServer : uniqueServers) {
            assertTrue(HostAddress.contains(uniqueServer), "Displayed Server is not present in the Pcap file");
            HostAddress.remove(uniqueServer);
        }

    }

    /**
     * BLEICHENBACHER SERVER TEST TESTING THE PCAP WHICH HAS RSA AND ECDH KEY EXCHANGE SESSIONS EXPECTED OUTPUT : 1
     * SERVER (127.0.0.1:443)
     */
    @Test
    public void testRsaServerSelectionFromDhPcap() {
        List<PcapSession> sessions = fetchSessions("Sample2.pcapng");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(1, uniqueServers.size(), "Expected count of server displayed for user");
        assertEquals("127.0.0.1:443", uniqueServers.get(0), "Expected Destination server");

    }

    /**
     * BLEICHENBACHER SERVER TEST TESTING THE PCAP WHICH HAS RSA AS KEY EXCHANGE FOR ALL TLS VERSIONS(EXCEPT TLS1.3)
     * EXPECTED OUTPUT : 4 SERVERS
     */
    @Test
    public void testRsaServerDisplayForAllTlsVersions() {
        List<String> HostAddress = new ArrayList<String>(
            Arrays.asList("127.0.0.1:4433", "127.0.0.8:4433", "127.0.0.2:4433", "127.0.0.3:4433"));

        List<PcapSession> sessions = fetchSessions("TLS_RSA_WITH_ARIA_128_CBC_SHA256.pcapng");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(4, uniqueServers.size(), "Expected count of server displayed for user");
        for (String uniqueServer : uniqueServers) {
            assertTrue(HostAddress.contains(uniqueServer), "Displayed Server is not present in the Pcap file");
            HostAddress.remove(uniqueServer);
        }

    }

    /**
     * BLEICHENBACHER SESSION COUNT TEST TESTING THE PCAP WHICH SSLV3 CONNECTIONS EXPECTED OUTPUT : 6 SESSIONS FROM 4
     * SERVERS
     */
    @Test
    public void testRsaSessionCount() {
        List<String> HostAddress = new ArrayList<String>(
            Arrays.asList("207.46.113.78:5443", "65.54.186.19:5443", "65.54.186.19:443", "207.46.113.78:443"));
        List<Integer> SessionCount = new ArrayList<Integer>(Arrays.asList(2, 1, 1, 2));
        int numberOfSessions = 0;

        List<PcapSession> sessions = fetchSessions("SSLV3_pcap.pcap");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        // List<String> uniqueServers = new ArrayList(serverSessionsMap.keySet());
        for (int i = 0; i < HostAddress.size(); i++) {
            String hostAddress = HostAddress.get(i);
            // System.out.println(hostAddress);

            numberOfSessions = serverSessionsMap.get(hostAddress).size();
            // System.out.println(numberOfSessions);

            assertEquals(Integer.parseInt(SessionCount.get(i).toString()), numberOfSessions,
                "Session count of server : " + hostAddress);

        }

    }

    /*
     * BLEICHENBACHER SESSION COUNT TEST TESTING A PCAP WHICH CONTAINS MORE NUMBER OF SESSIONS BETWEEN 2 SYSTEMS
     * EXPECTED OUTPUT : 2 SERVERS 1 WITH 36 SESSIONS AND ANOTHER HAS 12 SESSIONS.
     */

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testRsaSessionCountForBigFile() {
        List<String> HostAddress = new ArrayList<String>(Arrays.asList("127.0.0.4:4433", "127.0.0.3:4433"));
        List<Integer> SessionCount = new ArrayList<Integer>(Arrays.asList(36, 12));
        int numberOfSessions = 0;

        List<PcapSession> sessions = fetchSessions("Sample5.pcapng");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        // List<String> uniqueServers = new ArrayList(serverSessionsMap.keySet());
        for (int i = 0; i < HostAddress.size(); i++) {
            String hostAddress = HostAddress.get(i);
            // System.out.println(hostAddress);

            numberOfSessions = serverSessionsMap.get(hostAddress).size();
            // System.out.println(numberOfSessions);

            assertEquals(Integer.parseInt(SessionCount.get(i).toString()), numberOfSessions,
                "Session count of server : " + hostAddress);

        }

    }

    // ############################################### NOT IMPLEMENTED #####################################

    /*
     * BLEICHENBACHER SESSION COUNT TEST TESTING A PCAP WHICH CONTAINS ONLY ONE SESSION THIS FEATURE IS NOT YET
     * IMPLEMENTED
     */

    @Test
    @Disabled("To be implemented")
    public void testRsaSessionCountWithPsk() {
        int numberOfSessions = 0;

        List<PcapSession> sessions = fetchSessions("psk_captured.pcapng");
        BleichenbacherServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
        for (String hostAddress : uniqueServers) {
            numberOfSessions = serverSessionsMap.get(hostAddress).size();
        }

        assertEquals(1, numberOfSessions, "Session count of server");

    }
}