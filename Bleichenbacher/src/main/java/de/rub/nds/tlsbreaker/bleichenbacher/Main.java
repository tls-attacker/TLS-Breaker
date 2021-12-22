/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapAnalyzer;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
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
        try {
            String serverToAttack = getServerFromUser(bleichenbacherCommandConfig);
            bleichenbacherCommandConfig.getClientDelegate().setHost(serverToAttack);
        } catch (UnsupportedOperationException e) {
            CONSOLE.error("Invalid server selected");
            return;
        }

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

    private static String getServerFromUser(BleichenbacherCommandConfig bleichenbacherCommandConfig) {
        // TODO: testing server list
        // List<String> serverList = Arrays.asList("cloud.nds.rub.de:40064", "server2", "server3", "server4");
        List<String> serverList = new ArrayList<>();
        PcapAnalyzer pcapAnalyzer = new PcapAnalyzer(bleichenbacherCommandConfig.getPcapFileLocation());
        List<PcapSession> sessions = pcapAnalyzer.getAllSessions();
        // TODO: is there a better way to loop?
        for (int i = 0; i < sessions.size(); i++) {
            LOGGER.info("****** sessions size: " + sessions.size());
            LOGGER.info("****** session: " + sessions.get(i));
            LOGGER.info("****** session clientKEY: " + sessions.get(i).getClientKeyExchangeMessage());
            LOGGER.info("****** session source: " + sessions.get(i).getPacketSoruce());
            LOGGER.info("****** session distination: " + sessions.get(i).getPacketDestination().substring(0));
            serverList.add(sessions.get(i).getPacketDestination().substring(1) + ":"
                + sessions.get(i).getPacketPortDestination().replace(" (unknown)", ""));
        }

        displayListOfServers(serverList);
        String selectedServer = null;
        Scanner sc = new Scanner(System.in);
        try {
            int serverNumber = sc.nextInt();
            if (serverNumber > 0 & serverNumber <= serverList.size()) {
                selectedServer = serverList.get(serverNumber - 1);
                LOGGER.info("Selected server: " + selectedServer);
            } else {
                throw new UnsupportedOperationException();
            }
        } catch (Exception e) {
            throw new UnsupportedOperationException();
        }

        return selectedServer;
    }

    private static void displayListOfServers(List<String> serverList) {
        CONSOLE.info("Found " + serverList.size() + " server that can be vulnerable to Bleichenbacher.");
        for (int i = 0; i < serverList.size(); i++) {
            CONSOLE.info(i + 1 + ") " + serverList.get(i));
        }
        CONSOLE.info("Please select a server to check for vulnerability and launch an attack.");
        CONSOLE.info("Server number: ");
    }
}
