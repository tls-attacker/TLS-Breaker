/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;

import java.util.List;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

public class ConsoleInteractor {

    public static void DisplaySessionInfo(List<PcapSession> sessions) {
        for (int i = 0; i < sessions.size(); i++) {
            PcapSession session = sessions.get(i);
            CONSOLE.info(
                i + 1 + ") Destination=" + session.getDestinationHost() + "     Source=" + session.getSourceHost());
        }
    }
}
