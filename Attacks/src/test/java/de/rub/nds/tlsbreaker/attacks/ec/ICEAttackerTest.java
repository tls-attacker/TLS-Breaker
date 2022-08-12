/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.ec;

import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsbreaker.attacks.ec.oracles.TestECOracle;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class ICEAttackerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Test
    @Tag(TestCategories.SLOW_TEST)
    @Disabled("To be fixed")
    public void testAttack() {
        CONSOLE.info("Starting ICEAttacker test... this may take some time");
        TestECOracle oracle = new TestECOracle(NamedGroup.SECP256R1);
        ICEAttacker attacker = new ICEAttacker(oracle, ICEAttacker.ServerType.ORACLE, 4, NamedGroup.SECP256R1);
        BigInteger result = attacker.attack();

        LOGGER.debug(result);
        LOGGER.debug(oracle.getPrivateKey());

        assertEquals(oracle.getPrivateKey(), result);
    }
}
