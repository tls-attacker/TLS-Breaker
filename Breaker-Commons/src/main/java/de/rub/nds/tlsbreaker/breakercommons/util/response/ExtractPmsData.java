/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.util.response;

import java.io.EOFException;

import java.util.Arrays;
import java.util.concurrent.TimeoutException;
import java.nio.charset.StandardCharsets;

import org.apache.commons.codec.binary.Hex;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapHandle.TimestampPrecision;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.Pcaps;

import org.pcap4j.packet.Packet;

import org.pcap4j.packet.TcpPacket;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;

@SuppressWarnings("javadoc")
public class ExtractPmsData {

    // public ExtractPmsData()
    private static final int COUNT = 5;
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String PCAP_FILE = "sample.pcapng";

    // private ReadPacketFile() {}
    public String pmsDataExtracterFunction() throws PcapNativeException, NotOpenException {

        PcapHandle handle;
        // PcapDumper dumppac;
        try {
            handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
        } catch (PcapNativeException e) {
            handle = Pcaps.openOffline(PCAP_FILE);
            // dumppac = Pcaps.openOffline(PCAP_FILE);
        }

        for (int i = 0; i < COUNT; i++) {
            try {
                Packet packet = handle.getNextPacketEx();

                TcpPacket tcpPacket = packet.get(TcpPacket.class);

                if (i == 2) {
                    byte[] packet_hex_stream = packet.getRawData();

                    byte[] pms_data = Arrays.copyOfRange(packet_hex_stream, 77, 205);

                    LOGGER.info(Hex.encodeHex(pms_data));
                    return new String(Hex.encodeHex(pms_data));
                }

//                System.out.println(packet);
//                  dumppac.dump(packet);

            } catch (TimeoutException e) {
            } catch (EOFException e) {
                System.out.println("EOF");
                break;
            }

        }

        handle.close();
        return null;
    }

    public static void main(String[] args) {

    }
}
