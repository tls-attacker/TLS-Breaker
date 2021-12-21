/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;

public class PcapSession {
    /**
     * A PcapSession holds messages of TLS handshake (depending on implementation phase the messages it contains may
     * change) and information from the TCP packet header like the source and destination of the package.
     * 
     */

    private ClientKeyExchangeMessage clientKeyExchangeMessage;

    private String packetSoruce;

    private String packetDestination;

    public PcapSession(String source, String destination, ClientKeyExchangeMessage ckeMessage) {
        clientKeyExchangeMessage = ckeMessage;
        packetSoruce = source;
        packetDestination = destination;
    }

    public String getPacketSoruce() {
        return this.packetSoruce;
    }

    public void setPacketSoruce(String packetSoruce) {
        this.packetSoruce = packetSoruce;
    }

    public String getPacketDestination() {
        return this.packetDestination;
    }

    public void setPacketDestination(String packetDestination) {
        this.packetDestination = packetDestination;
    }

    public ClientKeyExchangeMessage getClientKeyExchangeMessage() {
        return this.clientKeyExchangeMessage;
    }

    public void setClientKeyExchangeMessage(ClientKeyExchangeMessage clientKeyExchangeMessage) {
        this.clientKeyExchangeMessage = clientKeyExchangeMessage;
    }

}
