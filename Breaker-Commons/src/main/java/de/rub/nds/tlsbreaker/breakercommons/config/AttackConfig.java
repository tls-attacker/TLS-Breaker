/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.config;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;

/** */
public abstract class AttackConfig extends TLSDelegateConfig {

    @Parameter(
            names = {"-skipConnectionCheck", "-skip_connection_check"},
            description =
                    "If set to true the Attacker will not check if the " + "target is reachable.")
    private boolean skipConnectionCheck = false;

    /**
     * @param delegate
     */
    public AttackConfig(GeneralDelegate delegate) {
        super(delegate);
    }

    /**
     * @return
     */
    public abstract boolean isExecuteAttack();

    /**
     * @return
     */
    public boolean isSkipConnectionCheck() {
        return skipConnectionCheck;
    }

    /**
     * @param skipConnectionCheck
     */
    public void setSkipConnectionCheck(boolean skipConnectionCheck) {
        this.skipConnectionCheck = skipConnectionCheck;
    }
}
