/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class BleichenbacherServerSelectionTest {

    public List<PcapSession> fetchSessions(String pcapFile) {
        PcapAnalyzer sample =
                new PcapAnalyzer(String.format("src/test/resources/pcap_files/%s", pcapFile));
        return sample.getAllSessions();
    }

    public static Stream<Arguments> provideUniqueServerSelectionTestVectors() {
        return Stream.of(
                Arguments.of("DH_RSA.pcapng", 0, List.of()),
                Arguments.of("2nd_TLS_RSA_PSK_AES.pcapng", 1, List.of("127.0.0.1:4433")),
                Arguments.of(
                        "SSLV3_pcap.pcap",
                        4,
                        List.of(
                                "207.46.113.78:5443",
                                "65.54.186.19:5443",
                                "65.54.186.19:443",
                                "207.46.113.78:443")),
                Arguments.of("psk_captured.pcapng", 1, List.of("127.0.0.1:4433")),
                Arguments.of("Sample2.pcapng", 1, List.of("127.0.0.1:443")),
                Arguments.of(
                        "TLS_RSA_WITH_ARIA_128_CBC_SHA256.pcapng",
                        4,
                        List.of(
                                "127.0.0.1:4433",
                                "127.0.0.8:4433",
                                "127.0.0.2:4433",
                                "127.0.0.3:4433")));
    }

    @ParameterizedTest
    @MethodSource("provideUniqueServerSelectionTestVectors")
    public void testUniqueServerSelection(
            String providedPcapFile,
            int expectedUniqueServerSessionCount,
            List<String> expectedUniqueServerSessions) {
        List<PcapSession> sessions = fetchSessions(providedPcapFile);
        BleichenbacherServerSelection bleichenbacherServerSelection =
                new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap =
                bleichenbacherServerSelection.getServerSessionsMap();
        List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());

        assertEquals(
                expectedUniqueServerSessionCount,
                uniqueServers.size(),
                "Expected count of server displayed for user");
        for (int i = 0; i < uniqueServers.size(); i++) {
            assertEquals(
                    expectedUniqueServerSessions.get(i),
                    uniqueServers.get(i),
                    "Expected Destination server");
        }
    }

    @Test
    @Tag(TestCategories.SLOW_TEST)
    public void testUniqueServerSelectionSlow() {
        testUniqueServerSelection(
                "Sample4.pcap",
                10,
                Arrays.asList(
                        "207.46.113.78:5443",
                        "204.9.163.181:443",
                        "65.54.186.19:5443",
                        "65.54.186.19:443",
                        "72.14.213.120:443",
                        "72.14.213.147:443",
                        "72.14.213.132:443",
                        "207.46.113.78:443",
                        "184.85.226.161:443",
                        "67.215.65.132:443"));
    }

    public static Stream<Arguments> provideRsaSessionCountTestVectors() {
        return Stream.of(
                Arguments.of(
                        "SSLV3_pcap.pcap",
                        List.of(
                                "207.46.113.78:5443",
                                "65.54.186.19:5443",
                                "65.54.186.19:443",
                                "207.46.113.78:443"),
                        List.of(2, 1, 1, 2)),
                Arguments.of(
                        "Sample5.pcapng",
                        List.of("127.0.0.4:4433", "127.0.0.3:4433"),
                        List.of(36, 12)));
    }

    @ParameterizedTest
    @MethodSource("provideRsaSessionCountTestVectors")
    public void testRsaSessionCount(
            String providedPcapFile,
            List<String> providedServers,
            List<Integer> expectedSessionCount) {
        List<PcapSession> sessions = fetchSessions(providedPcapFile);
        BleichenbacherServerSelection bleichenbacherServerSelection =
                new BleichenbacherServerSelection(sessions);
        Map<String, List<PcapSession>> serverSessionsMap =
                bleichenbacherServerSelection.getServerSessionsMap();
        for (int i = 0; i < providedServers.size(); i++) {
            int numberOfSessions = serverSessionsMap.get(providedServers.get(i)).size();
            assertEquals(
                    expectedSessionCount.get(i),
                    numberOfSessions,
                    String.format(
                            "Session count of server %s does not equal expectations",
                            providedServers.get(i)));
        }
    }
}
