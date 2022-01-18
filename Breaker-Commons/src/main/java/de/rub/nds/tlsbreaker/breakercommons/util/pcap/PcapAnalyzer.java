/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

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
import de.rub.nds.tlsattacker.core.state.TlsContext;

import org.bouncycastle.util.encoders.Hex;
import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;

import java.util.AbstractMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;

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

        List<Entry<IpV4Packet, TcpPacket>> collectedPackages = getSessionPackets();

        for (Entry<IpV4Packet, TcpPacket> p : collectedPackages) {

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

                    Record record = (Record) ar;

                    ProtocolVersion pversion =
                        ProtocolVersion.getProtocolVersion(record.getProtocolVersion().getValue());

                    Config config = Config.createConfig();

                    // We try to get only ClientHello, ServerHello, and ClientKeyExchange, other
                    // messages are ignored.

                    if (record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
                        System.out.println(getRecordHandshakeMessageType(record));

                        try {
                            HandshakeMessageParser<RSAClientKeyExchangeMessage> rsaparser =
                                new RSAClientKeyExchangeParser(0, record.getProtocolMessageBytes().getValue(), pversion,
                                    config);

                            // System.out.println(ar.getContentMessageType());
                            RSAClientKeyExchangeMessage msg = rsaparser.parse();

                            if (msg.getType().getValue() == msg.getHandshakeMessageType().getValue()) {

                                pcapSessions.add(new PcapSession(
                                    p.getKey().getHeader().getSrcAddr().toString().replaceFirst("/", ""),
                                    p.getKey().getHeader().getDstAddr().toString().replaceFirst("/", ""),
                                    p.getValue().getHeader().getSrcPort().toString().replace(" (unknown)", ""),
                                    p.getValue().getHeader().getDstPort().toString().replace(" (unknown)", ""), msg));
                            }

                        } catch (Exception e) {

                            // System.out.println("Message not compatible");
                            continue;
                        }
                    }

                    // System.out.println("-------------------------------------------------");
                }
            } catch (ParserException pe) {
                // System.out.println("The package could not be parsed");
                continue;
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

            /** 
             * Apply filtering to get only TLS packets (At the moment a bit tricky since TLS filter and packet support in pcap4j is yet to come)
             * The filet used is taken from the link above (Last time worked Jan 11 2021).
             * https://www.netmeister.org/blog/tcpdump-ssl-and-tls.html*/ 
            String filter = "(((tcp[((tcp[12] & 0xf0) >> 2)] = 0x14) || (tcp[((tcp[12] & 0xf0) >> 2)] = 0x15) ||"
            +" (tcp[((tcp[12] & 0xf0) >> 2)] = 0x17)) && (tcp[((tcp[12] & 0xf0) >> 2)+1] = 0x03 &&"
            +" (tcp[((tcp[12] & 0xf0) >> 2)+2] < 0x03)))   ||   (tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) &&"
            +" (tcp[((tcp[12] & 0xf0) >> 2)+1] = 0x03) && (tcp[((tcp[12] & 0xf0) >> 2)+9] = 0x03) &&"
            +" (tcp[((tcp[12] & 0xf0) >> 2)+10] < 0x03)    ||    (((tcp[((tcp[12] & 0xf0) >> 2)] < 0x14) ||"
            +" (tcp[((tcp[12] & 0xf0) >> 2)] > 0x18)) && (tcp[((tcp[12] & 0xf0) >> 2)+3] = 0x00) && (tcp[((tcp[12] & 0xf0) >> 2)+4] = 0x02))";
            BpfProgram bpfFilter =
                handle.compileFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE, PcapHandle.PCAP_NETMASK_UNKNOWN);
            handle.setFilter(bpfFilter);
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

    /**
     * Given that the record is of type Handshake, one can check which message type it contains
     * 
     * @param  record
     *                The record which contains the handshake message.
     * 
     * @return        The type of handshake message.
     */
    private HandshakeMessageType getRecordHandshakeMessageType(Record record) {
        if (record.getProtocolMessageBytes().getValue().length != 0) {
            byte typeBytes = record.getProtocolMessageBytes().getValue()[0];
            return HandshakeMessageType.getMessageType(typeBytes);
        }
        return HandshakeMessageType.UNKNOWN;

    }

}
