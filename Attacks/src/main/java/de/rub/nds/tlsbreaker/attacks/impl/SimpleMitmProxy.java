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
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowExecutorFactory;
import de.rub.nds.tlsattacker.core.workflow.action.executor.WorkflowExecutorType;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.attacks.config.SimpleMitmProxyCommandConfig;

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
        Config conf = Config.createConfig();
        conf.setWorkflowTraceType(WorkflowTraceType.SIMPLE_MITM_PROXY);
        State state = new State(conf);

        WorkflowExecutor workflowExecutor =
            WorkflowExecutorFactory.createWorkflowExecutor(WorkflowExecutorType.DEFAULT, state);
        workflowExecutor.executeWorkflow();
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
