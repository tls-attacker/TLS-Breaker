/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 * <p>
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

public class ServerSelection {

    private static final Logger LOGGER = LogManager.getLogger();

    public String getUserSelectedServer(List<PcapSession> sessions) {
        List<String> serverList = getUniqueServers(sessions);
        displayListOfServers(serverList);
        return getServerFromUser(serverList);
    }

    public List<String> getUniqueServers(List<PcapSession> sessions) {
        Set<String> serverSet = new HashSet<>();
        sessions.forEach(pcapSession -> serverSet.add(pcapSession.getDestinationHost()));
        return new ArrayList<>(serverSet);
    }

    private static String getServerFromUser(List<String> serverList) {
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
