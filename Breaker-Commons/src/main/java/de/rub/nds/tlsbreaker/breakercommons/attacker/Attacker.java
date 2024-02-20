/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.attacker;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsbreaker.breakercommons.config.AttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.connectivity.ConnectivityChecker;
import java.io.IOException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class Attacker<AttConfigT extends AttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected AttConfigT config;

    private final Config baseConfig;

    protected Attacker(AttConfigT config, Config baseConfig) {
        this.config = config;
        this.baseConfig = baseConfig;
    }

    public void run() throws IOException {
        if (!config.isSkipConnectionCheck() && !canConnect()) {
            CONSOLE.warn("Cannot reach Server. Is the server online?");
            throw new IOException("Server unreachable");
        }

        if (config.isExecuteAttack()) {
            LOGGER.debug("Attacking with: {}", this.getClass().getSimpleName());
            executeAttack();
        } else {
            LOGGER.debug("Checking with: {}", this.getClass().getSimpleName());
            VulnerabilityType res = isVulnerable();
            if (res == null) {
                LOGGER.warn("Got no vulnerability status - this should not happen");
            } else {
                LOGGER.info("Vulnerability status: {}", res);
            }
        }
    }

    @Deprecated
    public void attack() {
        // TODO replace more dryly using run or the internal executeAttack
        LOGGER.debug("Attacking with: " + this.getClass().getSimpleName());
        if (!config.isSkipConnectionCheck()) {
            if (!canConnect()) {
                CONSOLE.warn("Cannot reach Server. Is the server online?");
                return;
            }
        }
        executeAttack();
    }

    @Deprecated
    public VulnerabilityType checkVulnerability() {
        // TODO replace more dryly using run or the internal isVulnerable
        LOGGER.debug("Checking: " + this.getClass().getSimpleName());
        if (!config.isSkipConnectionCheck()) {
            if (!canConnect()) {
                CONSOLE.warn("Cannot reach Server. Is the server online?");
                return null;
            } else {
                LOGGER.debug("Can connect to server. Running vulnerability scan");
            }
        }
        return isVulnerable();
    }

    /** Executes a given attack. */
    protected abstract void executeAttack();

    /**
     * Checks whether a server is vulnerable without executing the full atatck.
     *
     * @return true if the server is vulnerable
     */
    protected abstract VulnerabilityType isVulnerable();

    public AttConfigT getConfig() {
        return config;
    }

    public Config getTlsConfig() {
        if (!config.hasDifferentConfig() && baseConfig == null) {
            return config.createConfig();
        } else {
            return config.createConfig(baseConfig);
        }
    }

    public Config getBaseConfig() {
        return baseConfig.createCopy();
    }

    protected boolean canConnect() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker =
                new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }
}
