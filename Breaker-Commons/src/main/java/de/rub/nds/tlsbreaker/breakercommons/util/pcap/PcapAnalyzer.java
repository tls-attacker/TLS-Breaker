/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.PskRsaClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ServerHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientHelloParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.DHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ECDHClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.HandshakeMessageParser;
import de.rub.nds.tlsattacker.core.protocol.parser.PskClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.PskDhClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.PskRsaClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.protocol.parser.ServerHelloParser;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import de.rub.nds.tlsattacker.util.ConsoleLogger;

import org.bouncycastle.crypto.util.CipherFactory;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PcapAnalyzer {

    private static final Logger LOGGER = LogManager.getLogger();

    private final String pcapFileLocation;
    private PcapHandle handle;
    PcapSession psession;
    LinkedHashMap<Long, List<Packet>> packets = new LinkedHashMap<Long, List<Packet>>();

    Map<Integer, PcapSession> pcapSessions = new HashMap<>();

    public PcapAnalyzer(String pcapFileLocation) {
        this.pcapFileLocation = pcapFileLocation;

        try {
            this.getPacketsFromPcapFile();
        } catch (NotOpenException e) {
            CONSOLE.warn("The pcap file could not be found!");
            e.printStackTrace();
        }
    }

    /**
     * Get a list PcapSessions that are extracted from the PcapFie
     * 
     * @see PcapSesession.java for the definition of a session.
     */
    public List<PcapSession> getAllSessions() {

        LOGGER.debug("Extracting the packages");

        for (Long id : packets.keySet()) {

            List<Packet> list = packets.get(id);

            byte[] defragmentedBytes = defragment(list);

            try {
                LOGGER.debug("Parsing the records");
                TlsContext context = new TlsContext();

                TlsRecordLayer rec_layer = new TlsRecordLayer(context);

                List<AbstractRecord> allRecords;
                if (defragmentedBytes != null && defragmentedBytes.length != 0) {
                    allRecords = rec_layer.parseRecords(defragmentedBytes);
                } else {
                    continue;
                }

                LOGGER.debug("Parsing records to specific TLS messages");
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

                        // ClientKeyExchange is parsed based on the selected cipher suite
                        ClientKeyExchangeMessage ckeMessage = parseToCKEMessage(record, foundSession);

                        switch (getRecordHandshakeMessageType(record)) {
                            case CLIENT_HELLO:
                                foundSession.setClientHelloMessage((ClientHelloMessage) tlsMessage);
                                break;
                            case SERVER_HELLO:
                                foundSession.setServerHellomessage((ServerHelloMessage) tlsMessage);
                                break;
                            case CLIENT_KEY_EXCHANGE:
                                foundSession.setClientKeyExchangeMessage(ckeMessage);
                                break;
                            default:
                                break;
                        }
                    }
                }
            } catch (ParserException pe) {
                LOGGER.debug("Package could not be parsed to a TLS message!");
                continue;
            }
        }
        return new ArrayList<PcapSession>(pcapSessions.values());
    }

    private ClientKeyExchangeMessage parseToCKEMessage(Record record, PcapSession session) {

        ClientKeyExchangeMessage msg = null;

        ProtocolVersion pversion = ProtocolVersion
                .getProtocolVersion(record.getProtocolVersion().getValue());

        Config config = Config.createConfig();

        if (getRecordHandshakeMessageType(record) == HandshakeMessageType.CLIENT_KEY_EXCHANGE) {

            if (session.getServerHellomessage() != null) {

                ServerHelloMessage shm = session.getServerHellomessage();

                CipherSuite selectedCipherSuite = CipherSuite
                        .getCipherSuite(shm.getSelectedCipherSuite().getValue());

                if (selectedCipherSuite.name().contains("TLS_RSA_PSK")) {
                    msg = new PskRsaClientKeyExchangeParser(0,
                            record.getProtocolMessageBytes().getValue(),
                            pversion, config).parse();

                }
                else if (selectedCipherSuite.name().contains("TLS_DH_PSK")) {
                    msg = new PskDhClientKeyExchangeParser(0,
                            record.getProtocolMessageBytes().getValue(),
                            pversion, config).parse();
                }
                else if (selectedCipherSuite.name().contains("TLS_PSK_")) {
                    msg = new PskClientKeyExchangeParser(0,
                            record.getProtocolMessageBytes().getValue(),
                            pversion, config).parse();
                }
                 else if (selectedCipherSuite.name().contains("TLS_ECDH_RSA")) {
                    msg = new ECDHClientKeyExchangeParser<ECDHClientKeyExchangeMessage>(0,
                            record.getProtocolMessageBytes().getValue(),
                            pversion, config).parse();
                    // System.out.println(msg.getPublicKey());

                } else if (selectedCipherSuite.name().contains("TLS_RSA")) {
                    msg = new RSAClientKeyExchangeParser<RSAClientKeyExchangeMessage>(0,
                            record.getProtocolMessageBytes().getValue(),
                            pversion, config).parse();
                    // System.out.println(msg.getPublicKey());

                } else if (selectedCipherSuite.name().contains("TLS_DH_")) {
                    msg = new DHClientKeyExchangeParser<>(0, record.getProtocolMessageBytes().getValue(),
                            pversion, config).parse();
                }
                else {
                    LOGGER.debug("ClientKeyExchange message not yet supported!");
                }
            }
        }
        return msg;
    }

    private HandshakeMessage parseToTLSMessage(Record record, HandshakeMessageType messageType) {

        ProtocolVersion pversion = ProtocolVersion
                .getProtocolVersion(record.getProtocolVersion().getValue());

        Config config = Config.createConfig();

        HandshakeMessage msg = null;

        try {
            if (messageType == HandshakeMessageType.CLIENT_HELLO) {
                ClientHelloParser clientHelloParser = new ClientHelloParser(0,
                        record.getProtocolMessageBytes().getValue(),
                        pversion, config);

                msg = clientHelloParser.parse();
            } else if (messageType == HandshakeMessageType.SERVER_HELLO) {
                ServerHelloParser serverHelloParser = new ServerHelloParser(0,
                        record.getProtocolMessageBytes().getValue(), pversion, config);

                msg = serverHelloParser.parse();
            }
        } catch (ParserException e) {
            LOGGER.debug("Could not parse the message!");
        }
        return msg;
    }

    private void getPacketsFromPcapFile() throws NotOpenException {
        try {
            handle = Pcaps.openOffline(pcapFileLocation, TimestampPrecision.NANO);

            // Filter the packages that pcap4j captures (TLS not yet supported)
            // String filter = "(((tcp[((tcp[12] & 0xf0) >> 2)] = 0x14) || (tcp[((tcp[12] & 0xf0) >> 2)] = 0x15) || (tcp[((tcp[12] & 0xf0) >> 2)] = 0x17)) && (tcp[((tcp[12] & 0xf0) >> 2)+1] = 0x03) && (tcp[((tcp[12] & 0xf0) >> 2)+2] < 0x03)))";
            // String filter = "(((tcp[((tcp[12] & 0xf0) >> 2)] = 0x14) || (tcp[((tcp[12] & 0xf0) >> 2)] = 0x15) || (tcp[((tcp[12] & 0xf0) >> 2)] = 0x17)) &&  (tcp[((tcp[12] & 0xf0) >> 2)+1] = 0x03) &&  (tcp[((tcp[12] & 0xf0) >> 2)+2] < 0x03)))";
        //    String filter = "(tcp[((tcp[12] & 0xf0) >> 2)+2] < 0x03)";
        // String filter ="((tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >> 2)+1] = 0x03) && (tcp[((tcp[12] & 0xf0) >> 2)+9] = 0x03) &&  (tcp[((tcp[12] & 0xf0) >> 2)+10] < 0x03))";
            
        // String filter = "tcp && (((tcp[((tcp[12] & 0xf0) >> 2)] = 0x14) || (tcp[((tcp[12] & 0xf0) >> 2)] = 0x15) || (tcp[((tcp[12] & 0xf0) >> 2)] = 0x17)) && (tcp[((tcp[12] & 0xf0) >> 2)+1] = 0x03 && (tcp[((tcp[12] & 0xf0) >> 2)+2] < 0x03)))   ||   (tcp[((tcp[12] & 0xf0) >> 2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >> 2)+1] = 0x03) && (tcp[((tcp[12] & 0xf0) >> 2)+9] = 0x03) && (tcp[((tcp[12] & 0xf0) >> 2)+10] < 0x03)    ||    (((tcp[((tcp[12] & 0xf0) >> 2)] < 0x14) || (tcp[((tcp[12] & 0xf0) >> 2)] > 0x18)) && (tcp[((tcp[12] & 0xf0) >> 2)+3] = 0x00) && (tcp[((tcp[12] & 0xf0) >> 2)+4] = 0x02))";
        // String filter = "tcp[tcp[12]>>2:4]&0xFFFFFCC0=0x17030000";
        // String filter = "tcp[tcpflags] & (tcp-syn|tcp-ack) != 0";
        // String filter = "!(tcp[tcpflags] & (tcp-syn|tcp-fin) != 0)";
        // String filter = "tcp && (tcp[((tcp[12] & 0xf0) >>2)] = 0x16) && (tcp[((tcp[12] & 0xf0) >>2)+9] = 0x03) && (tcp[((tcp[12] & 0xf0) >>2)+10] = 0x03))";
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
                LOGGER.debug("Could not defragment package!");
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
