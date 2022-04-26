/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import java.util.*;

public abstract class ServerSelection {

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

    protected abstract List<PcapSession> filterServers(List<PcapSession> sessions);
}
