/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.impl;

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
import de.rub.nds.tlsbreaker.invalidcurve.config.InvalidCurveAttackConfig;

public class InvalidCurvePcapFileHandler implements PcapFileHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    InvalidCurveAttackConfig invalidCurveAttackConfig;

    public InvalidCurvePcapFileHandler(InvalidCurveAttackConfig invalidCurveAttackConfig) {
        this.invalidCurveAttackConfig = invalidCurveAttackConfig;
    }

    public void handlePcapFile() {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(invalidCurveAttackConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (!sessions.isEmpty()) {
            ServerSelection invalidCurveServerSelection = new InvalidCurveServerSelection(sessions);
            Map<String, List<PcapSession>> serverSessionsMap = invalidCurveServerSelection.getServerSessionsMap();
            List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
            if (!uniqueServers.isEmpty()) {
                CONSOLE.info("Found " + uniqueServers.size() + " servers from the pcap file.");
                ConsoleInteractor consoleInteractor = new ConsoleInteractor();
                consoleInteractor.displayServers(uniqueServers, serverSessionsMap);
                String userOption = consoleInteractor.getValidUserSelection(uniqueServers);
                if ("N".equals(userOption)) {
                    CONSOLE.info("Execution of the attack cancelled.");
                } else if ("a".equals(userOption)) {
                    checkVulnerabilityOfAllServersAndDisplay(uniqueServers, invalidCurveAttackConfig, consoleInteractor,
                        serverSessionsMap);
                } else if (isCommaSeparatedList(userOption)) {
                    List<String> hosts = new ArrayList<>();
                    Arrays.stream(userOption.split(",")).forEach(
                        serverNumber -> hosts.add(uniqueServers.get(Integer.parseInt(trim(serverNumber)) - 1)));

                    checkVulnerabilityOfAllServersAndDisplay(hosts, invalidCurveAttackConfig, consoleInteractor,
                        serverSessionsMap);
                } else {
                    String host = uniqueServers.get(Integer.parseInt(userOption) - 1);
                    LOGGER.info("Selected server: " + host);
                    invalidCurveAttackConfig.getClientDelegate().setHost(host);
                    Boolean vulnerability = checkVulnerability(invalidCurveAttackConfig);
                    if (Objects.equals(vulnerability, Boolean.TRUE)) {
                        CONSOLE.info("Server " + host + " is vulnerable.");
                        CONSOLE.info("Do you want to execute the attack? (y/n):");
                        String userResponse = consoleInteractor.getUserYesNoResponse();
                        if ("Y".equals(userResponse)) {
                            executeAttack(host, invalidCurveAttackConfig);
                        } else if ("N".equals(userResponse)) {
                            CONSOLE.info("Execution of the attack cancelled.");
                        }
                    } else {
                        CONSOLE.info("The server " + host + " is not vulnerable.");
                    }
                }
            } else {
                CONSOLE.info("\nFound no potential servers for Invalid Curve Attack.");
            }
        } else {
            CONSOLE.info("No TLS handshake message found.");
        }
    }

    private void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueServers,
        InvalidCurveAttackConfig invalidCurveAttackConfig, ConsoleInteractor consoleInteractor,
        Map<String, List<PcapSession>> serverSessionsMap) {
        List<String> vulnerableServers = getVulnerableServers(uniqueServers, invalidCurveAttackConfig);
        CONSOLE.info("Found " + vulnerableServers.size() + "  vulnerable server.");
        if (!vulnerableServers.isEmpty()) {
            consoleInteractor.displayServers(vulnerableServers, serverSessionsMap);
        }
        if (vulnerableServers.size() == 1) {
            CONSOLE.info("Do you want to execute the attack? (y/n):");
            String userResponse = consoleInteractor.getUserYesNoResponse();
            if ("Y".equals(userResponse)) {
                String host = vulnerableServers.get(0);
                executeAttack(host, invalidCurveAttackConfig);
            } else if ("N".equals(userResponse)) {
                CONSOLE.info("Execution of the attack cancelled.");
            }
        } else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a server number to execute an attack.");
            CONSOLE.info("server number: ");
            int serverNumber = consoleInteractor.getUserSelectedServer(uniqueServers);
            String host = uniqueServers.get(serverNumber - 1);
            executeAttack(host, invalidCurveAttackConfig);
        }

    }

    private List<String> getVulnerableServers(List<String> uniqueServers,
        InvalidCurveAttackConfig invalidCurveAttackConfig) {

        List<String> vulnerableServers = new ArrayList<>();
        for (String server : uniqueServers) {
            invalidCurveAttackConfig.getClientDelegate().setHost(server);

            Attacker<? extends TLSDelegateConfig> attacker =
                new InvalidCurveAttacker(invalidCurveAttackConfig, invalidCurveAttackConfig.createConfig());

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

    private void executeAttack(String host, InvalidCurveAttackConfig invalidCurveAttackConfig) {

        invalidCurveAttackConfig.getClientDelegate().setHost(host);
        LOGGER.info("host=" + invalidCurveAttackConfig.getClientDelegate().getHost());

        Attacker<? extends TLSDelegateConfig> attacker =
            new InvalidCurveAttacker(invalidCurveAttackConfig, invalidCurveAttackConfig.createConfig());
        attacker.attack();
    }

    private boolean isCommaSeparatedList(String userOption) {
        return userOption.contains(",");
    }

    private Boolean checkVulnerability(InvalidCurveAttackConfig invalidCurveAttackConfig) {
        Attacker<? extends TLSDelegateConfig> attacker =
            new InvalidCurveAttacker(invalidCurveAttackConfig, invalidCurveAttackConfig.createConfig());
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
