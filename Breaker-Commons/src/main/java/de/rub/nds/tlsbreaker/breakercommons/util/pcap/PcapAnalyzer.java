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
import java.util.List;
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
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.exceptions.ParserException;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.layer.TlsRecordLayer;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.state.TlsContext;

public class PcapAnalyzer {

    private final String pcapFileLocation;
    private PcapHandle handle;
    private byte[] pms;
    PcapSession psession;

    public PcapAnalyzer(String pcapFileLocation) {
        this.pcapFileLocation = pcapFileLocation;
        try {
            this.getSessionPackets();
        } catch (NotOpenException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        PcapAnalyzer analyzer = new PcapAnalyzer("/home/bemore/Desktop/bb-session.pcapng");

        try {
            System.out.println(analyzer.getPreMasterSecret());
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    public byte[] getPreMasterSecret() {
        ProtocolVersion pversion = ProtocolVersion.TLS12;

        for (TcpPacket p : psession.getSessionFlights()) {

            try {
                TlsContext context = new TlsContext();

                TlsRecordLayer rec_layer = new TlsRecordLayer(context);

                List<AbstractRecord> allrecords = rec_layer.parseRecords(p.getPayload().getRawData());

                for (AbstractRecord ar : allrecords) {

                    Config config = Config.createConfig();

                    if (ar.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
                        try {
                            RSAClientKeyExchangeParser rsaparser = new RSAClientKeyExchangeParser(0,
                                ar.getProtocolMessageBytes().getValue(), pversion, config);
                            RSAClientKeyExchangeMessage msg = (RSAClientKeyExchangeMessage) rsaparser.parse();
                            pms = msg.getPublicKey().getValue();
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

        return pms;
    }

    private void getSessionPackets() throws NotOpenException {

        try {
            handle = Pcaps.openOffline(pcapFileLocation, TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            System.out.println("Can not find file");
            e.printStackTrace();
            // dumppac = Pcaps.openOffline(PCAP_FILE);
        }

        psession = new PcapSession();

        while (true) {

            Packet packet = handle.getNextPacket();

            if (packet == null) {
                break;
            }

            TcpPacket tcpPacket = packet.get(TcpPacket.class);

            System.out.println(tcpPacket);

            psession.addPacket(tcpPacket);
        }
    }

}
