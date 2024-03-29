/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.tlspoodle.impl;

import de.rub.nds.modifiablevariable.VariableModification;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.protocol.ProtocolMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.record.AbstractRecord;
import de.rub.nds.tlsattacker.core.record.Record;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.SendingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.VulnerabilityType;
import de.rub.nds.tlsbreaker.tlspoodle.config.TLSPoodleCommandConfig;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/** Executes a poodle attack. It logs an error in case the tested server is vulnerable to poodle. */
public class TLSPoodleAttacker extends Attacker<TLSPoodleCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * @param config
     * @param baseConfig
     */
    public TLSPoodleAttacker(TLSPoodleCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        throw new UnsupportedOperationException("Not implemented yet");
    }

    /**
     * @return
     */
    @Override
    public VulnerabilityType isVulnerable() {
        Config tlsConfig = getTlsConfig();
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);

        ModifiableByteArray padding = new ModifiableByteArray();
        // https://mta.openssl.org/pipermail/openssl-announce/2018-March/000119.html
        // Some implementations only test the least significant bit of each
        // byte.
        // https://yngve.vivaldi.net/2015/07/14/there-are-more-poodles-in-the-forest/
        // Update: 2022 - above link is down, use one of the following
        // https://yngve.vivaldi.net/there-are-more-poodles-in-the-forest/
        // https://web.archive.org/web/20200924084146/https://yngve.vivaldi.net/2015/07/14/there-are-more-poodles-in-the-forest/
        // 4800 servers test the last byte of the padding, but not the first.
        // 240 servers (which is much lower) check the first byte, but not the
        // last byte.
        // Therefore, we flip just the most significant bit of the first byte in
        // the padding.
        VariableModification<byte[]> modifier =
                ByteArrayModificationFactory.xor(new byte[] {(byte) 0x80}, 0);
        padding.setModification(modifier);
        Record finishedMessageRecord = new Record();
        finishedMessageRecord.prepareComputations();
        finishedMessageRecord.getComputations().setPadding(padding);

        insertModifiedFinishedMessageRecord(trace, finishedMessageRecord);

        State state = new State(tlsConfig, trace);

        try {
            WorkflowExecutor workflowExecutor =
                    WorkflowExecutorFactory.createWorkflowExecutor(
                            tlsConfig.getWorkflowExecutorType(), state);
            workflowExecutor.executeWorkflow();
        } catch (WorkflowExecutionException ex) {
            LOGGER.info("Not possible to finalize the defined workflow");
            LOGGER.debug(ex);
            return null;
        }
        if (state.getTlsContext().isReceivedFatalAlert()) {
            LOGGER.info(
                    "NOT Vulnerable. The modified message padding was identified, the server correctly responds with an alert message");
            return VulnerabilityType.NOT_VULNERABLE;
        } else if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.FINISHED, trace)) {
            LOGGER.info("Vulnerable (definitely), Finished message found");
            return VulnerabilityType.VULNERABLE;
        } else {
            LOGGER.info("Not vulnerable (probably), no Finished message found, yet also no alert");
            return VulnerabilityType.PROBABLY_NOT_VULNERABLE;
        }
    }

    private void insertModifiedFinishedMessageRecord(
            WorkflowTrace trace, Record finishedMessageRecord) {
        // We have to manually initialize the 3 records for the sending action,
        // since o/w they are not yet initialized at this stage.
        SendingAction lastSendingAction = WorkflowTraceUtil.getLastSendingAction(trace);
        List<ProtocolMessage> sendMessages = lastSendingAction.getSendMessages();
        assert (sendMessages.get(sendMessages.size() - 1) instanceof FinishedMessage);
        List<AbstractRecord> sendRecords = lastSendingAction.getSendRecords();
        sendRecords.add(new Record()); // Key Exchange
        sendRecords.add(new Record()); // CCS
        sendRecords.add(finishedMessageRecord);
    }
}
