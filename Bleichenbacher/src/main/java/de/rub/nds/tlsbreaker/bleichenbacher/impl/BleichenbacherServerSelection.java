/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.impl;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;

import java.util.ArrayList;
import java.util.List;

public class BleichenbacherServerSelection extends ServerSelection {

    public BleichenbacherServerSelection(List<PcapSession> sessions) {
        super(sessions);
    }

    @Override
    protected List<PcapSession> filterServers(List<PcapSession> sessions) {
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
