/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;

public class PcapSession {
    /**
     * A PcapSession holds messages of TLS handshake (depending on implementation
     * phase the messages it contains may
     * change) and information from the TCP packet header like the source and
     * destination of the package.
     * 
     */

    private HashSet<String> pcapIdentifier = new HashSet<>();

    private String packetSource;

    private String packetDestination;

    private String packetPortSource;

    private String packetPortDestination;

    private ClientKeyExchangeMessage clientKeyExchangeMessage;

    private ClientHelloMessage clientHelloMessage;

    private ServerHelloMessage serverHelloMessage;

    List<ApplicationMessage> applicationMessages = new ArrayList<>();

    public List<ApplicationMessage> getApplicationMessages() {
        return this.applicationMessages;
    }

    public void addApplicationMessage(ApplicationMessage applicationMessage){
        if(applicationMessage != null){
            this.applicationMessages.add(applicationMessage);
        }
    }

    public int getApplicationDataSize(){
        int total_size=0;
        for(ApplicationMessage am:applicationMessages){
            total_size += am.getData().getValue().length;
        }
        return total_size;
    }

    public PcapSession(String source, String destination, String packetPortSrc, String PackerPortDst) {
        packetSource = source;
        packetDestination = destination;
        packetPortSource = packetPortSrc;
        packetPortDestination = PackerPortDst;
    }

    public byte[] getPreMasterSecret() {
        return this.clientKeyExchangeMessage.getPublicKey().getValue();
    }

    public HashSet<String> getPcapIdentifier() {
        return this.pcapIdentifier;
    }

    public void setPcapIdentifier(HashSet<String> pcapIdentifier) {
        this.pcapIdentifier = pcapIdentifier;
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
        if (clientKeyExchangeMessage != null) {
            this.clientKeyExchangeMessage = clientKeyExchangeMessage;
        }
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

    public String getDestinationHost() {
        return this.packetDestination + ":" + this.packetPortDestination;
    }

    public String getSourceHost() {
        return this.packetSource + ":" + this.packetPortSource;
    }

    public ClientHelloMessage getClientHelloMessage() {
        return this.clientHelloMessage;
    }

    public void setClientHelloMessage(ClientHelloMessage clientHelloMessage) {
        if (clientHelloMessage != null) {
            this.clientHelloMessage = clientHelloMessage;
        }
    }

    public ServerHelloMessage getServerHellomessage() {
        return this.serverHelloMessage;
    }

    public void setServerHellomessage(ServerHelloMessage serverHelloMessage) {
        if (serverHelloMessage != null) {
            this.serverHelloMessage = serverHelloMessage;
        }

    }

}
