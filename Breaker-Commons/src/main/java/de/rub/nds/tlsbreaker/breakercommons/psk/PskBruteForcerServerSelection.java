/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.psk;

import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.PcapSession;
import de.rub.nds.tlsbreaker.breakercommons.util.pcap.ServerSelection;
import java.util.ArrayList;
import java.util.List;

public class PskBruteForcerServerSelection extends ServerSelection {

    public PskBruteForcerServerSelection(List<PcapSession> sessions) {
        super(sessions);
    }

    @Override
    protected List<PcapSession> filterServers(List<PcapSession> sessions) {
        List<PcapSession> filteredServers = new ArrayList<>();
        for (PcapSession s : sessions) {
            ServerHelloMessage shm = s.getServerHellomessage();
            ProtocolVersion selectedProtocol =
                    ProtocolVersion.getProtocolVersion(shm.getProtocolVersion().getValue());
            CipherSuite selectedCipher =
                    CipherSuite.getCipherSuite(shm.getSelectedCipherSuite().getValue());
            if ((selectedCipher.name().contains("TLS_RSA_PSK_")
                            || selectedCipher.name().contains("TLS_PSK_")
                            || selectedCipher.name().contains("TLS_DHE_PSK_"))
                    && !selectedProtocol.name().contains("TLS13")) {
                filteredServers.add(s);
            }
        }
        return filteredServers;
    }
}
