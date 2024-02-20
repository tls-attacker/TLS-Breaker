/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.heartbleed.impl;

import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;
import java.util.List;

public class HeartbleedServerSelection extends ServerSelection {

    public HeartbleedServerSelection(List<PcapSession> sessions) {
        super(sessions);
    }

    @Override
    protected List<PcapSession> filterServers(List<PcapSession> sessions) {
        return sessions;
    }
}
