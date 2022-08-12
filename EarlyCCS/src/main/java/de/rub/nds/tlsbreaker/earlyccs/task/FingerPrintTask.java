/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.earlyccs.task;

import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import de.rub.nds.tlsbreaker.breakercommons.util.response.ResponseExtractor;
import de.rub.nds.tlsbreaker.breakercommons.util.response.ResponseFingerprint;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;

public class FingerPrintTask extends TlsTask {

    private static final Logger LOGGER = LogManager.getLogger();

    private final State state;

    private ResponseFingerprint fingerprint;

    public FingerPrintTask(State state, int reexecutions) {
        super(reexecutions);
        this.state = state;
    }

    public FingerPrintTask(State state, long additionalTimeout, boolean increasingTimeout, int reexecutions,
        long additionalTcpTimeout) {
        super(reexecutions, additionalTimeout, increasingTimeout, additionalTcpTimeout);
        this.state = state;
    }

    @Override
    public boolean execute() {
        try {
            WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(state.getConfig().getWorkflowExecutorType(), state);
            executor.executeWorkflow();

            if (!state.getWorkflowTrace().executedAsPlanned()) {
                return false;
            }
            fingerprint = ResponseExtractor.getFingerprint(state);

            if (fingerprint == null) {
                return false;
            }
            return true;
        } finally {
            try {
                state.getTlsContext().getTransportHandler().closeConnection();
            } catch (IOException ex) {
                LOGGER.debug(ex);
            }
        }
    }

    public State getState() {
        return state;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public void reset() {
        state.reset();
    }
}
