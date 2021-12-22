/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import java.io.EOFException;
import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.concurrent.TimeoutException;

import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PcapAnalyzer {

    private final String pcapFileLocation;
    private PcapHandle handle;
    private List<Entry<IpV4Packet, TcpPacket>> sessionPackets = Collections.synchronizedList(new ArrayList<>());
    PcapSession psession;

    public PcapAnalyzer(String pcapFileLocation) {
        this.pcapFileLocation = pcapFileLocation;
        try {
            this.getPacketsFromPcapFile();
        } catch (NotOpenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public byte[] getPreMasterSecret(ClientKeyExchangeMessage chosenCKEMessage) {
        return chosenCKEMessage.getPublicKey().getValue();

    }

    /**
     * Get a list PcapSessions that are extracted from the PcapFie
     * 
     * @see PcapSesession.java for the definition of a session.
     */
    public List<PcapSession> getAllSessions() {

        List<PcapSession> pcapSessions = new ArrayList<>();

        for (Entry<IpV4Packet, TcpPacket> p : getSessionPackets()) {

            try {
                TlsContext context = new TlsContext();

                TlsRecordLayer rec_layer = new TlsRecordLayer(context);

                List<AbstractRecord> allrecords;
                if (p.getValue().getPayload() != null) {
                    allrecords = rec_layer.parseRecords(p.getValue().getPayload().getRawData());
                } else {
                    continue;
                }

                for (AbstractRecord ar : allrecords) {

                    Record thisRecord = (Record) ar;

                    ProtocolVersion pversion =
                        ProtocolVersion.getProtocolVersion(thisRecord.getProtocolVersion().getValue());

                    Config config = Config.createConfig();

                    // We try to get only ClientHello, ServerHello, and ClientKeyExchange, other
                    // messages are ignored.
                    if (ar.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {

                        try {
                            HandshakeMessageParser<RSAClientKeyExchangeMessage> rsaparser =
                                new RSAClientKeyExchangeParser(0, ar.getProtocolMessageBytes().getValue(), pversion,
                                    config);

                            // System.out.println(ar.getContentMessageType());
                            RSAClientKeyExchangeMessage msg = rsaparser.parse();

                            if (msg.getType().getValue() == msg.getHandshakeMessageType().getValue()) {

                                pcapSessions.add(new PcapSession(p.getKey().getHeader().getSrcAddr().toString(),
                                    p.getKey().getHeader().getDstAddr().toString(),
                                    p.getValue().getHeader().getSrcPort().toString(),p.getValue().getHeader().getDstPort().toString(), msg));
                            }

                        } catch (Exception e) {

                            System.out.println("Message not compatible");
                            continue;
                        }
                    }

                    System.out.println("-------------------------------------------------");
                }
            } catch (ParserException pe) {
                System.out.println("The package could not be parsed");

            }

        }
        return pcapSessions;
    }

    public List<Entry<IpV4Packet, TcpPacket>> getSessionPackets() {
        return sessionPackets;
    }

    private void getPacketsFromPcapFile() throws NotOpenException {

        try {
            handle = Pcaps.openOffline(pcapFileLocation, TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            System.out.println("Can not find file");
        }

        while (true) {

            Packet packet = handle.getNextPacket();

            if (packet == null) {
                break;
            }

            TcpPacket tcpPacket = packet.get(TcpPacket.class);

            IpV4Packet ipPacket = packet.get(IpV4Packet.class);

            if (tcpPacket == null) {
                break;
            }

            Entry<IpV4Packet, TcpPacket> e = new AbstractMap.SimpleEntry<>(ipPacket, tcpPacket);
            sessionPackets.add(e);
        }
    }

}
