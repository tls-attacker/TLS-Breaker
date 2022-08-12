/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.task;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.DefaultWorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsbreaker.breakercommons.cca.CcaCertificateManager;
import de.rub.nds.tlsbreaker.breakercommons.cca.CcaWorkflowGenerator;
import de.rub.nds.tlsbreaker.breakercommons.cca.vector.CcaVector;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class CcaTask extends TlsTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private final CcaVector ccaVector;
    private State state;
    private final Config tlsConfig;
    private final CcaCertificateManager ccaCertificateManager;

    public CcaTask(CcaVector ccaVector, Config tlsConfig, CcaCertificateManager ccaCertificateManager,
        int reexecutions) {
        super(reexecutions);
        this.ccaVector = ccaVector;
        this.tlsConfig = tlsConfig;
        this.ccaCertificateManager = ccaCertificateManager;
    }

    public CcaTask(CcaVector ccaVector, Config tlsConfig, CcaCertificateManager ccaCertificateManager,
        long additionalTimeout, boolean increasingTimeout, int reexecutions, long additionalTcpTimeout) {
        super(reexecutions, additionalTimeout, increasingTimeout, additionalTcpTimeout);
        this.ccaVector = ccaVector;
        this.tlsConfig = tlsConfig;
        this.ccaCertificateManager = ccaCertificateManager;
    }

    private State prepareState() {
        WorkflowTrace trace = CcaWorkflowGenerator.generateWorkflow(tlsConfig, ccaCertificateManager,
            ccaVector.getCcaWorkflowType(), ccaVector.getCcaCertificateType());
        State state = new State(tlsConfig, trace);
        return state;
    }

    @Override
    public boolean execute() {
        state = prepareState();
        try {
            WorkflowExecutor executor = new DefaultWorkflowExecutor(state);
            executor.executeWorkflow();
            return true;
        } finally {
            try {
                state.getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    }

    public CcaVector getCcaVector() {
        return ccaVector;
    }

    public State getState() {
        return state;
    }

    @Override
    public void reset() {
        state.reset();
    }

}
