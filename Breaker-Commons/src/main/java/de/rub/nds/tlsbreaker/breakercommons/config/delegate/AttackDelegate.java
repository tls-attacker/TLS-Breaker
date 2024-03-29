/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;

/** A Delegate which can be used by Attacks if they implement also an exploitation functionality */
public class AttackDelegate extends Delegate {

    @Parameter(
            names = {"-executeAttack", "-execute_attack"},
            description =
                    "If this value is set the Attack is not only Tested, but also "
                            + "executed (WARNING)")
    private boolean executeAttack = false;

    /** Default Constructor */
    public AttackDelegate() {}

    /**
     * Returns true if an attack should be executed
     *
     * @return true if an attack should be executed
     */
    public boolean isExecuteAttack() {
        return executeAttack;
    }

    /**
     * Sets executeAttack flag to the specified value
     *
     * @param executeAttack the value to set executeAttack to
     */
    public void setExecuteAttack(boolean executeAttack) {
        this.executeAttack = executeAttack;
    }

    /**
     * Does nothing
     *
     * @param config Ignored
     * @throws ConfigurationException Never thrown
     */
    @Override
    public void applyDelegate(Config config) throws ConfigurationException {}
}
