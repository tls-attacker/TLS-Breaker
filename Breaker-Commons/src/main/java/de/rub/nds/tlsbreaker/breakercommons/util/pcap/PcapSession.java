/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.pcap4j.packet.TcpPacket;

public class PcapSession {

    private final List<TcpPacket> sessionFlights = Collections.synchronizedList(new ArrayList<>());

    public void addPacket(TcpPacket tcp) {
        sessionFlights.add(tcp);

    }

    public List<TcpPacket> getSessionFlights() {
        return Collections.unmodifiableList(sessionFlights);
    }

}
