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
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
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

    Map<Integer, PcapSession> pcapSessions = new HashMap<>();

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

        for (Long id : packets.keySet()) {

            List<Packet> list = packets.get(id);

            byte[] defragmentedBytes = defragment(list);

            try {
                TlsContext context = new TlsContext();

                TlsRecordLayer rec_layer = new TlsRecordLayer(context);

                List<AbstractRecord> allRecords;
                if (defragmentedBytes != null && defragmentedBytes.length != 0) {
                    allRecords = rec_layer.parseRecords(defragmentedBytes);
                } else {
                    continue;
                }

                for (AbstractRecord ar : allRecords) {

                    Record record = (Record) ar;

                    if (record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {

                        HandshakeMessage tlsMessage = parseToTLSMessage(record, getRecordHandshakeMessageType(record));

                        IpV4Packet ipPacket = list.get(0).get(IpV4Packet.class);

                        TcpPacket tcpPacket = list.get(0).get(TcpPacket.class);

                        PcapSession foundSession = new PcapSession(ipPacket.getHeader().getSrcAddr().getHostAddress(),
                                ipPacket.getHeader().getDstAddr().getHostAddress(),
                                tcpPacket.getHeader().getSrcPort().valueAsString(),
                                tcpPacket.getHeader().getDstPort().valueAsString());

                        // Addresses and ports are added in a HashSet whose HashCode will identify a
                        // Handshake(Stream in Wireshark)
                        foundSession.getPcapIdentifier().add(ipPacket.getHeader().getSrcAddr().getHostAddress());
                        foundSession.getPcapIdentifier().add(ipPacket.getHeader().getDstAddr().getHostAddress());
                        foundSession.getPcapIdentifier().add(tcpPacket.getHeader().getSrcPort().valueAsString());
                        foundSession.getPcapIdentifier().add(tcpPacket.getHeader().getDstPort().valueAsString());

                        if (pcapSessions.containsKey(foundSession.getPcapIdentifier().hashCode())) {
                            foundSession = pcapSessions.get(foundSession.getPcapIdentifier().hashCode());
                        } else {
                            pcapSessions.put(foundSession.getPcapIdentifier().hashCode(), foundSession);

                        }

                        switch (getRecordHandshakeMessageType(record)) {
                            case CLIENT_HELLO:
                                foundSession.setClientHelloMessage((ClientHelloMessage) tlsMessage);
                                break;
                            case SERVER_HELLO:
                                foundSession.setServerHellomessage((ServerHelloMessage) tlsMessage);
                                break;
                            case CLIENT_KEY_EXCHANGE:
                                foundSession.setClientKeyExchangeMessage((ClientKeyExchangeMessage) tlsMessage);
                                break;
                            default:
                                break;
                        }
                    }
                }
            } catch (ParserException pe) {
                // The packages that can not be parsed are ignored.
                continue;
            }

        }

        return new ArrayList<PcapSession>(pcapSessions.values());
    }

    private HandshakeMessage parseToTLSMessage(Record record, HandshakeMessageType messageType) {

        ProtocolVersion pversion = ProtocolVersion
                .getProtocolVersion(record.getProtocolVersion().getValue());

        Config config = Config.createConfig();

        HandshakeMessage msg = null;

        System.out.println(getRecordHandshakeMessageType(record));

        try {
            if (messageType == HandshakeMessageType.CLIENT_KEY_EXCHANGE) {
                ClientKeyExchangeParser<RSAClientKeyExchangeMessage> rsaParser = new RSAClientKeyExchangeParser(0,
                        record.getProtocolMessageBytes().getValue(), pversion,
                        config);

                msg = rsaParser.parse();
            } else if (messageType == HandshakeMessageType.CLIENT_HELLO) {
                ClientHelloParser clientHelloParser = new ClientHelloParser(0,
                        record.getProtocolMessageBytes().getValue(),
                        pversion, config);

                msg = clientHelloParser.parse();
            } else if (messageType == HandshakeMessageType.SERVER_HELLO) {
                ServerHelloParser serverHelloParser = new ServerHelloParser(0,
                        record.getProtocolMessageBytes().getValue(), pversion, config);

                msg = serverHelloParser.parse();
            }

        } catch (Exception e) {
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

                if (pack.get(TcpPacket.class) != null) {
                    TcpPacket tcpPacket = pack.get(TcpPacket.class);

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
        if (record.getProtocolMessageBytes().getValue().length != 0
                && record.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
            byte typeBytes = record.getProtocolMessageBytes().getValue()[0];
            return HandshakeMessageType.getMessageType(typeBytes);
        }
        return HandshakeMessageType.UNKNOWN;
    }

}
