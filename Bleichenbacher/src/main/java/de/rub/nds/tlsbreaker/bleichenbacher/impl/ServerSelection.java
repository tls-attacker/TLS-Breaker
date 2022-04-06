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

import java.util.*;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

public class ServerSelection {

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

    public String getValidUserSelection(List<String> uniqueServers, ConsoleInteractor consoleInteractor) {
        if (uniqueServers.size() == 1) {
            CONSOLE.info("Do you want to check the vulnerability of the server? (y/n):");
            return consoleInteractor.getUserDecisionForOneServer();
        } else {
            CONSOLE.info("Please select server numbers to check for vulnerability "
                                 + "or press 'a' to check for vulnerability of all the servers.");
            CONSOLE.info("Select Option: ");
            return consoleInteractor.getUserInputForMultipleServers(uniqueServers);
        }
    }

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
}
