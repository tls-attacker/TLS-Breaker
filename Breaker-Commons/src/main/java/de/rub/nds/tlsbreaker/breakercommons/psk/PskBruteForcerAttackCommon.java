/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.psk;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.psk.config.PskBruteForcerAttackCommonCommandConfig;
import de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider.GuessProvider;
import de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider.GuessProviderFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class PskBruteForcerAttackCommon<
                T extends PskBruteForcerAttackCommonCommandConfig, S>
        extends Attacker<T> {
    private static final Logger LOGGER = LogManager.getLogger();

    protected PskBruteForcerAttackCommon(T config, Config baseConfig) {
        super(config, baseConfig);
    }

    @Override
    protected void executeAttack() {
        S attackState = prepareAttackState();

        GuessProvider guessProvider =
                GuessProviderFactory.createGuessProvider(
                        config.getGuessProviderType(), config.getGuessProviderInputStream());

        int counter = 0;
        long startTime = System.currentTimeMillis();
        while (guessProvider.hasNext()) {
            byte[] guess = guessProvider.next();
            counter++;
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Testing: {}", ArrayConverter.bytesToHexString(guess));
            }
            boolean found = tryPsk(guess, attackState);
            if (found) {
                long duration = System.currentTimeMillis() - startTime;
                long totalSeconds = duration / 1000;
                CONSOLE.info(
                        "Found the psk in {} min {} sec", totalSeconds / 60, totalSeconds % 60);
                CONSOLE.info("Guessed {} times", counter);
                break;
            }
        }
    }

    protected abstract S prepareAttackState();

    protected abstract boolean tryPsk(byte[] guess, S attackState);
}
