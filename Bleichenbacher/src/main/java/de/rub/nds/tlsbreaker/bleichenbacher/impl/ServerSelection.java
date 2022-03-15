/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 * <p>
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.*;

public class ServerSelection {
    private static final Logger LOGGER = LogManager.getLogger();

    private Map<String, List<PcapSession>> serverSessionsMap = new HashMap<>();

    public ServerSelection(List<PcapSession> sessions) {
        initializeServerSessionsMap(sessions);
    }

    private void initializeServerSessionsMap(List<PcapSession> sessions) {
        List<PcapSession> filteredServers = filterServers(sessions);
        filteredServers.forEach(pcapSession -> {
            String destinationHost = pcapSession.getDestinationHost();
            if (serverSessionsMap.containsKey(destinationHost)) {
                serverSessionsMap.get(destinationHost).add(pcapSession);
            } else {
                serverSessionsMap.put(destinationHost, new ArrayList<>(Arrays.asList(pcapSession)));
            }
        });
    }

    public Map<String, List<PcapSession>> getServerSessionsMap() {
        return this.serverSessionsMap;
    }

    public String getValidUserSelection(List<String> uniqueServers) {
        // List<String> serverList = getServers(sessions);
        // displayListOfServers(sessions);
        return getUserInput(uniqueServers);
    }

    // TODO: used at 2 places
    /*
     * public List<String> getServers(List<PcapSession> sessions) { List<String> serverList = new ArrayList<>();
     * sessions.forEach(pcapSession -> serverList.add(pcapSession.getDestinationHost())); return serverList; }
     */
    private List<PcapSession> filterServers(List<PcapSession> sessions) {
        List<PcapSession> filteredServers = new ArrayList<>();
        for (PcapSession s : sessions) {
            if (s.getClientKeyExchangeMessage() != null) {
                ServerHelloMessage shm = s.getServerHellomessage();
                CipherSuite selectedCipher = CipherSuite.getCipherSuite(shm.getSelectedCipherSuite().getValue());
                if (selectedCipher.name().contains("TLS_RSA")) {
                    filteredServers.add(s);
                }
            }
        }
        return filteredServers;
    }

    private String getUserInput(List<String> uniqueServers) {
        String selectedServer = null;
        Scanner sc = new Scanner(System.in);
        try {
            if (sc.hasNextInt()) {
                int serverNumber = sc.nextInt();
                if (serverNumber > 0 && serverNumber <= uniqueServers.size()) {
                    /*
                     * selectedServer = sessions.get(serverNumber - 1).getDestinationHost();
                     * LOGGER.info("Selected server: " + selectedServer);
                     */
                    return Integer.toString(serverNumber);
                } else {
                    throw new UnsupportedOperationException();
                }
            } else {
                String userOption = sc.nextLine();
                if ("a".equals(userOption)) {
                    return userOption;
                } else {
                    throw new UnsupportedOperationException();
                }
            }
        } catch (Exception e) {
            throw new UnsupportedOperationException();
        }

        // return selectedServer;
    }

    /*
     * private void displayListOfServers(List<PcapSession> sessions) { CONSOLE.info("Found " + sessions.size() +
     * " sessions from the pcap file."); DisplaySessionInfo(sessions);
     *//*
     * for (int i = 0; i < serverList.size(); i++) { CONSOLE.info(i + 1 + ") " + serverList.get(i)); }
     *//*
     * CONSOLE.info("a) Check if all the above servers are vulnerable.");
     * CONSOLE.info("Please select a server number to check for vulnerability " +
     * "or press 'a' to check for vulnerability of all the servers."); CONSOLE.info("Select Option: "); }
     */
}
