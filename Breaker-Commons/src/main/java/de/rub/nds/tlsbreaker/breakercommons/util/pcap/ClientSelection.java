/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import java.util.*;

public abstract class ClientSelection {
    private Map<String, List<PcapSession>> clientSessionsMap = new HashMap<>();

    public ClientSelection(List<PcapSession> sessions) {
        initializeClientSessionsMap(sessions);
    }

    private void initializeClientSessionsMap(List<PcapSession> sessions) {
        List<PcapSession> filteredclient = filterClient(sessions);
        filteredclient.forEach(
                pcapSession -> {
                    String sourceClient = pcapSession.getSourceHost();
                    if (clientSessionsMap.containsKey(sourceClient)) {
                        clientSessionsMap.get(sourceClient).add(pcapSession);
                    } else {
                        clientSessionsMap.put(
                                sourceClient, new ArrayList<>(Arrays.asList(pcapSession)));
                    }
                });
    }

    public Map<String, List<PcapSession>> getClientSessionsMap() {
        return this.clientSessionsMap;
    }

    protected abstract List<PcapSession> filterClient(List<PcapSession> sessions);
}
