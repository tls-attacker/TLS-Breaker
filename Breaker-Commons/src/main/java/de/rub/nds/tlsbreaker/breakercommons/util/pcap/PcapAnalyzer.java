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
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
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

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

public class PcapAnalyzer {

    private final String pcapFileLocation;
    private PcapHandle handle;
    // private List<Entry<IpV4Packet, TcpPacket>> sessionPackets =
    // Collections.synchronizedList(new ArrayList<>());
    PcapSession psession;
    Map<Long, List<Packet>> packets = new HashMap<Long, List<Packet>>();

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

        for (Long id : packets.keySet()) {

            List<Packet> list = packets.get(id);

            byte[] defragmentedBytes = defragment(list);

            try {
                TlsContext context = new TlsContext();

                TlsRecordLayer rec_layer = new TlsRecordLayer(context);

                List<AbstractRecord> allrecords;
                if (defragmentedBytes != null) {
                    allrecords = rec_layer.parseRecords(defragmentedBytes);
                } else {
                    continue;
                }

                for (AbstractRecord ar : allrecords) {

                    Record record = (Record) ar;

                    System.out.println(getRecordHandshakeMessageType(record));

                    // We try to get only ClientHello, ServerHello, and ClientKeyExchange, other
                    // messages are ignored.

                    if (getRecordHandshakeMessageType(record) == HandshakeMessageType.CLIENT_KEY_EXCHANGE
                            && record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {

                        HandshakeMessage msg = parseToTLSMessage(record, HandshakeMessageType.CLIENT_KEY_EXCHANGE);

                        IpV4Packet ipPacket = list.get(0).get(IpV4Packet.class);

                        TcpPacket tcpPacket = list.get(0).get(TcpPacket.class);

                        pcapSessions.add(new PcapSession(ipPacket.getHeader().getSrcAddr().getHostAddress(),
                                ipPacket.getHeader().getDstAddr().getHostAddress(),
                                tcpPacket.getHeader().getSrcPort().valueAsString(),
                                tcpPacket.getHeader().getDstPort().valueAsString(),
                                (ClientKeyExchangeMessage) msg));

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

    private HandshakeMessage parseToTLSMessage(Record record, HandshakeMessageType messageType) {

        ProtocolVersion pversion = ProtocolVersion
                .getProtocolVersion(record.getProtocolVersion().getValue());

        Config config = Config.createConfig();

        RSAClientKeyExchangeMessage msg = null;

        if (getRecordHandshakeMessageType(record) == messageType) {
            try {
                HandshakeMessageParser<RSAClientKeyExchangeMessage> rsaparser = new RSAClientKeyExchangeParser(0,
                        record.getProtocolMessageBytes().getValue(), pversion,
                        config);

                // System.out.println(ar.getContentMessageType());
                msg = rsaparser.parse();

            } catch (Exception e) {
            }
        }
        return msg;
    }

    private void getPacketsFromPcapFile() throws NotOpenException {

        try {
            handle = Pcaps.openOffline(pcapFileLocation, TimestampPrecision.NANO);

            String filter = "tcp";
            BpfProgram bpfFilter = handle.compileFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE,
                    PcapHandle.PCAP_NETMASK_UNKNOWN);
            handle.setFilter(bpfFilter);
        } catch (PcapNativeException e) {
            System.out.println("Can not find file");
        }

        while (true) {
            try {
                Packet packet = handle.getNextPacketEx();

                if (packet.get(TcpPacket.class) != null) {
                    long id = packet.get(TcpPacket.class).getHeader().getAcknowledgmentNumberAsLong();

                    // System.out.println(id);
                    if (packets.containsKey(id)) {
                        packets.get(id).add(packet);
                    } else {
                        List<Packet> list = new ArrayList<Packet>();
                        list.add(packet);
                        packets.put(id, list);
                    }
                } else {
                    continue;
                }

            } catch (TimeoutException e) {
                continue;
            } catch (EOFException e) {
                break;
            } catch (PcapNativeException e) {
                break;
            }
        }

    }

    private byte[] defragment(List<Packet> list) {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        for (Packet pack : list) {
            try {
                // System.out.println(tcpPacket.getHeader().getSequenceNumberAsLong());

                if (pack.get(TcpPacket.class) != null) {
                    TcpPacket tcpPacket = pack.get(TcpPacket.class);

                    System.out.println(tcpPacket.getHeader().getSequenceNumberAsLong() + " --- "
                            + tcpPacket.getHeader().getAcknowledgmentNumberAsLong());
                    if (tcpPacket.getPayload() != null) {
                        output.write(tcpPacket.getPayload().getRawData());
                    }
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        return output.toByteArray();
    }

    /**
     * Given that the record is of type Handshake, one can check which message type
     * it contains
     * 
     * @param record
     *               The record which contains the handshake message.
     * 
     * @return The type of handshake message.
     */
    private HandshakeMessageType getRecordHandshakeMessageType(Record record) {
        if (record.getProtocolMessageBytes().getValue().length != 0) {
            byte typeBytes = record.getProtocolMessageBytes().getValue()[0];
            return HandshakeMessageType.getMessageType(typeBytes);
        }
        return HandshakeMessageType.UNKNOWN;
    }

}
