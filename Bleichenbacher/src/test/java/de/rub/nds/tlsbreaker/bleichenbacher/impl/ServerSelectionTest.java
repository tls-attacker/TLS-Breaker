/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.impl;


import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.util.*;

public class ServerSelectionTest {

    private File FileLocation;

    public ServerSelectionTest() {
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

    /*
     * BLEICHENBACHER SERVER TEST
     * TESTING THE PCAP WHICH USES DIFFIE HELLMAN HAS KEY EXCHANGE EXPECTED OUTPUT : 0 SERVERS SINCE BLEICHENBACHER
     * WON'T WORK ON DIFFIE HELLMAN KEY EXCHANGE
     */
    @Test
    public void isServerDisplayedForDH() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "DH_RSA.pcapng" + File.separator);


        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        Assert.assertEquals("Expected count of server displayed for user", 0, uniqueServers.size());
    }

    /*
     * BLEICHENBACHER SERVER TEST
     * TESTING THE PCAP WHICH USES RSA KEY EXCHANGE EXPECTED OUTPUT : 1 SERVERS (127.0.0.1:4433)
     *
     */
    @Test
    public void isAllServerdisplayForRSA() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "2nd_TLS_RSA_PSK_AES.pcapng" + File.separator);

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        Assert.assertEquals("Expected count of server displayed for user", 1, uniqueServers.size());
        Assert.assertEquals("Expected Destination server", "127.0.0.1:4433", uniqueServers.get(0));

    }

    /*
     * BLEICHENBACHER SERVER TEST
     * TESTING THE PCAP WHICH USES RSA HAS KEY EXCHANGE WITH SSLV3 PROTOCOL
     * EXPECTED OUTPUT : 4 SERVERS.
     */
    @Test
    public void TestUniqueSSLV3Pcap() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "SSLV3_pcap.pcap" + File.separator);

        List<String> HostAddress =
            Arrays.asList("207.46.113.78:5443", "65.54.186.19:5443", "65.54.186.19:443", "207.46.113.78:443");
        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        Assert.assertEquals("Expected count of server displayed for user", 4, uniqueServers.size());
        for (int i = 0; i < uniqueServers.size(); i++) {
            Assert.assertEquals("Expected Destination server", HostAddress.get(i), uniqueServers.get(i));
        }

    }

    /*
     * BLEICHENBACHER SERVER TEST
     * TESTING THE PCAP WHICH USES RSA KEY EXCHANGE EXPECTED OUTPUT : 1 SERVERS (127.0.0.1:4433)
     */
    @Test
    public void testPcapWithExtraTlsDataInSessions() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "psk_captured.pcapng" + File.separator);

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        Assert.assertEquals("Expected count of server displayed for user", 1, uniqueServers.size());
        Assert.assertEquals("Expected Destination server", "127.0.0.1:4433", uniqueServers.get(0));

    }

    /*
     * BLEICHENBACHER SERVER TEST
     * TESTING THE PCAP WHICH USES RSA KEY EXCHANGE
     * EXPECTED OUTPUT : 10 SERVERS
     */
    @Test
    public void testBigPcapWithMultipleServers() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "Sample4.pcap" + File.separator);

        List<String> HostAddress = new ArrayList<String>(Arrays.asList("204.9.163.181:443", "65.54.186.19:5443",
            "65.54.186.19:443", "72.14.213.120:443", "72.14.213.147:443", "72.14.213.132:443", "207.46.113.78:443",
            "184.85.226.161:443", "67.215.65.132:443", "207.46.113.78:5443"));

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        Assert.assertEquals("Expected count of server displayed for user", 10, uniqueServers.size());
        for (String uniqueServer : uniqueServers) {

            Assert.assertTrue("Displayed Server is not present in the Pcap file",
                    HostAddress.contains(uniqueServer));
            HostAddress.remove(uniqueServer);
        }

    }

    /*
     * BLEICHENBACHER SERVER TEST
     * TESTING THE PCAP WHICH HAS RSA AND ECDH KEY EXCHANGE SESSIONS EXPECTED OUTPUT : 1 SERVER (127.0.0.1:443)
     */
    @Test
    public void TestRSAServerSelectionFromDHPcap() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "Sample2.pcapng" + File.separator);

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        Assert.assertEquals("Expected count of server displayed for user", 1, uniqueServers.size());
        Assert.assertEquals("Expected Destination server", "127.0.0.1:443", uniqueServers.get(0));

    }

    /*
     * BLEICHENBACHER SERVER TEST
     * TESTING THE PCAP WHICH HAS RSA AS KEY EXCHANGE FOR ALL TLS VERSIONS(EXCEPT TLS1.3) EXPECTED OUTPUT : 4 SERVERS
     */
    @Test
    public void TestRSAServerDisplayForAllTLSVersions() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "TLS_RSA_WITH_ARIA_128_CBC_SHA256.pcapng" + File.separator);

        List<String> HostAddress = new ArrayList<String>(
            Arrays.asList("127.0.0.1:4433", "127.0.0.8:4433", "127.0.0.2:4433", "127.0.0.3:4433"));

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        Assert.assertEquals("Expected count of server displayed for user", 4, uniqueServers.size());
        for (String uniqueServer : uniqueServers) {

            Assert.assertTrue("Displayed Server is not present in the Pcap file",
                    HostAddress.contains(uniqueServer));
            HostAddress.remove(uniqueServer);
        }

    }


    /*
     * BLEICHENBACHER SESSION COUNT TEST
     * TESTING THE PCAP WHICH SSLV3 CONNECTIONS
     *  EXPECTED OUTPUT : 6 SESSIONS FROM 4 SERVERS
     */
    @Test
    public void TestRSASessionscount() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "SSLV3_pcap.pcap" + File.separator);

        List<String> HostAddress = new ArrayList<String>(
            Arrays.asList("207.46.113.78:5443", "65.54.186.19:5443", "65.54.186.19:443", "207.46.113.78:443"));
        List<Integer> SessionCount = new ArrayList<Integer>(Arrays.asList(2, 1, 1, 2));
        int numberOfSessions = 0;

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        // List<String> uniqueServers = new ArrayList(serverSessionsMap.keySet());
        for (int i = 0; i < HostAddress.size(); i++) {
            String hostAddress = HostAddress.get(i);
            //System.out.println(hostAddress);

            numberOfSessions = serverSessionsMap.get(hostAddress).size();
            //System.out.println(numberOfSessions);

            Assert.assertEquals("Session count of server : " + hostAddress,
                Integer.parseInt(SessionCount.get(i).toString()), numberOfSessions);

        }

    }

    /*
     * BLEICHENBACHER SESSION COUNT TEST
     * TESTING A PCAP WHICH CONTAINS MORE NUMBER OF SESSIONS BETWEEN 2 SYSTEMS
     *  EXPECTED OUTPUT : 2 SERVERS
     * 1 WITH 36 SESSIONS AND ANOTHER HAS 12 SESSIONS.
     */

    @Test
    public void TestRSASessionsCountForBigFile() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "Sample5.pcapng" + File.separator);

        List<String> HostAddress = new ArrayList<String>(Arrays.asList("127.0.0.4:4433", "127.0.0.3:4433"));
        List<Integer> SessionCount = new ArrayList<Integer>(Arrays.asList(36, 12));
        int numberOfSessions = 0;

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        // List<String> uniqueServers = new ArrayList(serverSessionsMap.keySet());
        for (int i = 0; i < HostAddress.size(); i++) {
            String hostAddress = HostAddress.get(i);
            //System.out.println(hostAddress);

            numberOfSessions = serverSessionsMap.get(hostAddress).size();
            //System.out.println(numberOfSessions);

            Assert.assertEquals("Session count of server : " + hostAddress,
                Integer.parseInt(SessionCount.get(i).toString()), numberOfSessions);

        }

    }

    // ############################################### NOT IMPLEMENTED #####################################

    /*
     * BLEICHENBACHER SESSION COUNT TEST
     * TESTING A PCAP WHICH CONTAINS ONLY ONE SESSION
     * THIS FEATURE IS NOT YET IMPLEMENTED
     */

    // @Test
    public void TestRSAsessionscount() {

        FileLocation = new File("src" + File.separator + "test" + File.separator + "resources" + File.separator
                + "pcap_files" + File.separator + "psk_captured.pcapng" + File.separator);

        int numberOfSessions = 0;

        List<PcapSession> sessions = fetchsessions(FileLocation);
        ServerSelection serverSelection = new ServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
        for (String hostAddress : uniqueServers) {
            numberOfSessions = serverSessionsMap.get(hostAddress).size();
        }

        Assert.assertEquals("Session count of server", 1, numberOfSessions);

    }
}