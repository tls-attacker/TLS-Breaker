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

            // Apply filtering
            String filter = "tcp";
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

}
