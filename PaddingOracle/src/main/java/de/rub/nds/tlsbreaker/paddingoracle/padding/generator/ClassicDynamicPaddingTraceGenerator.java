/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.paddingoracle.padding.generator;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ApplicationMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.paddingoracle.config.PaddingRecordGeneratorType;
import de.rub.nds.tlsbreaker.paddingoracle.padding.vector.PaddingVector;
import java.util.LinkedList;

/** */
public class ClassicDynamicPaddingTraceGenerator extends PaddingTraceGenerator {

    /**
     * @param recordGeneratorType
     */
    public ClassicDynamicPaddingTraceGenerator(PaddingRecordGeneratorType recordGeneratorType) {
        super(recordGeneratorType);
    }

    /**
     * @param config
     * @return
     */
    @Override
    public WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector) {
        RunningModeType runningMode = config.getDefaultRunningMode();
        WorkflowConfigurationFactory factory = new WorkflowConfigurationFactory(config);
        WorkflowTrace trace =
                factory.createWorkflowTrace(WorkflowTraceType.DYNAMIC_HANDSHAKE, runningMode);

        if (runningMode == RunningModeType.SERVER) {
            // we assume that the client sends the first application message
            trace.addTlsAction(new ReceiveAction(new ApplicationMessage()));
        }
        ApplicationMessage applicationMessage = new ApplicationMessage(config);
        SendAction sendAction = new SendAction(applicationMessage);
        sendAction.setRecords(new LinkedList<>());
        sendAction.getRecords().add(vector.createRecord());
        trace.addTlsAction(sendAction);
        trace.addTlsAction(new GenericReceiveAction());

        return trace;
    }
}
