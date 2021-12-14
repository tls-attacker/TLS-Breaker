package de.rub.nds.tlsbreaker.breakercommons.util.pcap;

import java.io.EOFException;
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
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.parser.RSAClientKeyExchangeParser;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;

public class PcapAnalyzer {
	

	private static final String PCAP_FILE = "/home/bemore/Desktop/bb-session.pcapng";
	private PcapHandle handle;
	private byte[] pms;

//	public PcapAnalyzer(PcapHandle handle, String pcap_file) {
//		this.handle = handle;
//
//	}
	
	public PcapAnalyzer() {
		
	}
	
	
	public byte[] getPreMasterSecret() {
		try {
			findPremasterSecret();
		} catch (PcapNativeException | NotOpenException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return pms;
	}
	

	private void findPremasterSecret() throws PcapNativeException, NotOpenException {

		try {
			handle = Pcaps.openOffline(PCAP_FILE, TimestampPrecision.NANO);
		} catch (PcapNativeException e) {
			System.out.println("Can not find file");
			// dumppac = Pcaps.openOffline(PCAP_FILE);
		}

		while (true) {
			try {
				Packet packet = handle.getNextPacketEx();

				TcpPacket tcpPacket = packet.get(TcpPacket.class);

				ProtocolVersion pversion = ProtocolVersion.TLS12;

//                System.out.println(new String(Hex.encodeHex(bytearray)));

				RecordParser parser = new RecordParser(0, tcpPacket.getPayload().getRawData(), pversion);

				Record parsedRecord = parser.parse();
//                System.out.println(Hex.encodeHex(tcpPacket.getPayload().getRawData()));
//                System.out.println(Hex.encodeHex(parsedRecord.getProtocolMessageBytes().getValue()));

				System.out.println(parsedRecord.getLength());

				System.out.println(parsedRecord.getContentMessageType());

				Config config = Config.createConfig();
				
				if (parsedRecord.getContentMessageType() == ProtocolMessageType.APPLICATION_DATA) {
					break;
				}

				if (parsedRecord.getContentMessageType() == ProtocolMessageType.HANDSHAKE) {
					try {
						RSAClientKeyExchangeParser rsaparser = new RSAClientKeyExchangeParser(0,
								parsedRecord.getProtocolMessageBytes().getValue(), pversion, config);
						RSAClientKeyExchangeMessage msg = (RSAClientKeyExchangeMessage) rsaparser.parse();
						pms = msg.getPublicKey().getValue();
					} catch (Exception e) {
						
						System.out.println("Message not compatible");
						continue;
					}
				}

				System.out.println("-------------------------------------------------");

			} catch (TimeoutException e) {
			} catch (EOFException e) {
				System.out.println("EOF");
				break;
			}
		}
	}

}
