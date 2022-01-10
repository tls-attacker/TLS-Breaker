/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
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

    private String packetSource;

    private String packetDestination;

    private String packetPortSource;

    private String packetPortDestination;

    public PcapSession(String source, String destination, String packetPortSrc, String PackerPortDst,
        ClientKeyExchangeMessage ckeMessage) {
        packetSource = source;
        packetDestination = destination;
        packetPortSource = packetPortSrc;
        packetPortDestination = PackerPortDst;
        clientKeyExchangeMessage = ckeMessage;
    }

    public String getPacketSource() {
        return this.packetSource;
    }

    public void setPacketSource(String packetSource) {
        this.packetSource = packetSource;
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

    public String getPacketPortSource() {
        return this.packetPortSource;
    }

    public void setPacketPortSource(String packetPortSource) {
        this.packetPortSource = packetPortSource;
    }

    public String getPacketPortDestination() {
        return this.packetPortDestination;
    }

    public void setPacketPortDestination(String packetPortDestination) {
        this.packetPortDestination = packetPortDestination;
    }

}
