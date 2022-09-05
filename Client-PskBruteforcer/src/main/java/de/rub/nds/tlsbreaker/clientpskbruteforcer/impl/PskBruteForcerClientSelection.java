/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

//package de.rub.nds.tlsbreaker.serverpskbruteforce.impl;
package de.rub.nds.tlsbreaker.clientpskbruteforcer.impl;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
//import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ClientSelection;
import de.vandermeer.asciitable.AT_Row;

import java.util.ArrayList;
import java.util.List;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

public class PskBruteForcerClientSelection extends ClientSelection {

    public PskBruteForcerClientSelection(List<PcapSession> sessions) {
        super(sessions);
    }

    @Override
    protected List<PcapSession> filterClient(List<PcapSession> sessions) {
        List<PcapSession> filteredClients = new ArrayList<>();
        // List<PcapSession> newfilteredServers = new ArrayList<>();
        for (PcapSession s : sessions) {
            ServerHelloMessage shm = s.getServerHellomessage();
            ProtocolVersion selectedProtocol = ProtocolVersion.getProtocolVersion(shm.getProtocolVersion().getValue());
            CipherSuite selectedCipher = CipherSuite.getCipherSuite(shm.getSelectedCipherSuite().getValue());
            if ((selectedCipher.name().contains("TLS_RSA_PSK_") || selectedCipher.name().contains("TLS_PSK_")
                || selectedCipher.name().contains("TLS_DHE_PSK_")) && !selectedProtocol.name().contains("TLS13")) {
                filteredClients.add(s);

            }

        }
        return filteredClients;
//        final String[] previous_host = { " " };
//        filteredServers.forEach(pcapSession -> {
//            String sourceHost = pcapSession.getSourceHost();
//
//            String[] parts = sourceHost.split(":");
//            String portless_hostaddress = parts[0];
//            if (previous_host[0].equals(portless_hostaddress)) {
//                return;
//            }
//            previous_host[0] = portless_hostaddress;
//            newfilteredServers.add(pcapSession);
//        });

    }
}
