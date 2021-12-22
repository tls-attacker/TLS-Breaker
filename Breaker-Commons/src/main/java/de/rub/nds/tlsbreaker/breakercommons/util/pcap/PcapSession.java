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

    private String packetPortSoruce;

    public String getPacketPortSoruce() {
        return this.packetPortSoruce;
    }

    public void setPacketPortSoruce(String packetPortSoruce) {
        this.packetPortSoruce = packetPortSoruce;
    }

    public String getPacketPortDestination() {
        return this.packetPortDestination;
    }

    public void setPacketPortDestination(String packetPortDestination) {
        this.packetPortDestination = packetPortDestination;
    }

    private String packetPortDestination;

    public PcapSession(String source, String destination, String packetPortSrc, String PackerPortDst, ClientKeyExchangeMessage ckeMessage) {
        clientKeyExchangeMessage = ckeMessage;
        packetSoruce = source;
        packetDestination = destination;
        packetPortSoruce = packetPortSrc;
        packetPortDestination = PackerPortDst;
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
