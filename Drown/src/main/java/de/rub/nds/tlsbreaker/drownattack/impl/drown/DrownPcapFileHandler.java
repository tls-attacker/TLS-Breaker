/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.drownattack.impl.drown;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ConsoleInteractor;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;
import de.rub.nds.tlsbreaker.drownattack.config.BaseDrownCommandConfig;
import de.rub.nds.tlsbreaker.drownattack.config.GeneralDrownCommandConfig;
import de.rub.nds.tlsbreaker.drownattack.config.SpecialDrownCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.apache.commons.lang3.StringUtils.trim;

public class DrownPcapFileHandler {

    private static final Logger LOGGER = LogManager.getLogger();
    BaseDrownCommandConfig baseDrownCommandConfig;

    public DrownPcapFileHandler(BaseDrownCommandConfig baseDrownCommandConfig) {
        this.baseDrownCommandConfig = baseDrownCommandConfig;
    }

    public void handlePcapFile() {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(baseDrownCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (!sessions.isEmpty()) {
            ServerSelection serverSelection = new DrownServerSelection(sessions);
            Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
            List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
            if (!uniqueServers.isEmpty()) {
                CONSOLE.info("Found " + uniqueServers.size() + " servers from the pcap file.");
                ConsoleInteractor consoleInteractor = new ConsoleInteractor();
                consoleInteractor.displayServerAndPmsCount(uniqueServers, serverSessionsMap);
                String userOption = consoleInteractor.getValidUserSelection(uniqueServers);
                if ("N".equals(userOption)) {
                    CONSOLE.info("Execution of the attack cancelled.");
                } else if ("a".equals(userOption)) {
                    checkVulnerabilityOfAllServersAndDisplay(uniqueServers, baseDrownCommandConfig, serverSessionsMap,
                                                             consoleInteractor);
                } else if (isCommaSeparatedList(userOption)) {
                    List<String> hosts = new ArrayList<>();
                    Arrays.stream(userOption.split(",")).forEach(
                            serverNumber -> hosts.add(uniqueServers.get(Integer.parseInt(trim(serverNumber)) - 1)));

                    checkVulnerabilityOfAllServersAndDisplay(hosts, baseDrownCommandConfig, serverSessionsMap,
                                                             consoleInteractor);
                } else {
                    String host = uniqueServers.get(Integer.parseInt(userOption) - 1);
                    LOGGER.info("Selected server: " + host);
                    baseDrownCommandConfig.getClientDelegate().setHost(host);
                    Boolean vulnerability = checkVulnerability(baseDrownCommandConfig);
                    if (Objects.equals(vulnerability, Boolean.TRUE)) {
                        CONSOLE.info("Server " + host + " is vulnerable.");
                        CONSOLE.info("Do you want to execute the attack? (y/n):");
                        String userResponse = consoleInteractor.getUserYesNoResponse();
                        if ("Y".equals(userResponse)) {
                            executeAttack(host, serverSessionsMap, baseDrownCommandConfig);
                        } else if ("N".equals(userResponse)) {
                            CONSOLE.info("Execution of the attack cancelled.");
                        }
                    } else {
                        CONSOLE.info("The server " + host + " is not vulnerable.");
                    }
                }
            } else {
                CONSOLE.info("\nFound no potential servers for DROWN attack.");
            }
        } else {
            CONSOLE.info("No TLS handshake message found.");
        }
    }

    private void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueServers,
                                                          BaseDrownCommandConfig baseDrownCommandConfig, Map<String, List<PcapSession>> serverSessionsMap,
                                                          ConsoleInteractor consoleInteractor) {
        List<String> vulnerableServers = getVulnerableServers(uniqueServers, baseDrownCommandConfig);
        CONSOLE.info("Found " + vulnerableServers.size() + "  vulnerable server.");
        if (!vulnerableServers.isEmpty()) {
            consoleInteractor.displayServerAndPmsCount(vulnerableServers, serverSessionsMap);
        }
        if (vulnerableServers.size() == 1) {
            CONSOLE.info("Do you want to execute the attack? (y/n):");
            String userResponse = consoleInteractor.getUserYesNoResponse();
            if ("Y".equals(userResponse)) {
                String host = vulnerableServers.get(0);
                executeAttack(host, serverSessionsMap, baseDrownCommandConfig);
            } else if ("N".equals(userResponse)) {
                CONSOLE.info("Execution of the attack cancelled.");
            }
        } else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a server number to execute an attack.");
            CONSOLE.info("server number: ");
            int serverNumber = consoleInteractor.getUserSelectedServer(uniqueServers);
            String host = uniqueServers.get(serverNumber - 1);
            executeAttack(host, serverSessionsMap, baseDrownCommandConfig);
        }
    }

    private List<String> getVulnerableServers(List<String> uniqueServers,
                                              BaseDrownCommandConfig baseDrownCommandConfig) {
        List<String> vulnerableServers = new ArrayList<>();
        for (String server : uniqueServers) {
            baseDrownCommandConfig.getClientDelegate().setHost(server);

            Attacker<? extends TLSDelegateConfig> attacker = getAttacker(baseDrownCommandConfig);

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

    private void executeAttack(String host, Map<String, List<PcapSession>> serverSessionsMap,
                               BaseDrownCommandConfig baseDrownCommandConfig) {

        baseDrownCommandConfig.getClientDelegate().setHost(host);
        baseDrownCommandConfig.setPremasterSecretsFromPcap(getPreMasterSecrets(serverSessionsMap.get(host)));
        LOGGER.info(
                "host=" + baseDrownCommandConfig.getClientDelegate().getHost() + " and count of encrypted Premaster Secret="
                        + baseDrownCommandConfig.getPremasterSecretsFromPcap().size());

        Attacker<? extends TLSDelegateConfig> attacker = getAttacker(baseDrownCommandConfig);
        attacker.attack();
    }

    private List<byte[]> getPreMasterSecrets(List<PcapSession> hostSessions) {
        List<byte[]> preMasterSecrets = new ArrayList<>();
        for (PcapSession session : hostSessions) {
            preMasterSecrets.add(session.getPreMasterSecret());
        }
        return preMasterSecrets;
    }

    private boolean isCommaSeparatedList(String userOption) {
        return userOption.contains(",");
    }

    private Boolean checkVulnerability(BaseDrownCommandConfig baseDrownCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker = getAttacker(baseDrownCommandConfig);
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

    private Attacker<? extends TLSDelegateConfig> getAttacker(BaseDrownCommandConfig baseDrownCommandConfig) {
        if (baseDrownCommandConfig instanceof GeneralDrownCommandConfig) {
            GeneralDrownCommandConfig generalDrownConfig = (GeneralDrownCommandConfig) baseDrownCommandConfig;
            return new GeneralDrownAttacker(generalDrownConfig, generalDrownConfig.createConfig());
        } else if (baseDrownCommandConfig instanceof SpecialDrownCommandConfig) {
            SpecialDrownCommandConfig specialDrownConfig = (SpecialDrownCommandConfig) baseDrownCommandConfig;
            return new SpecialDrownAttacker(specialDrownConfig, specialDrownConfig.createConfig());
        } else
            return null;
    }
}
