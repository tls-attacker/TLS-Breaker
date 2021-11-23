/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.ec;

import de.rub.nds.tlsbreaker.heartbleed.ec.oracles.TestECOracle;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import de.rub.nds.tlsattacker.util.tests.SlowTests;
import java.math.BigInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import static org.junit.Assert.assertEquals;
import org.junit.Test;
import org.junit.experimental.categories.Category;

/**
 *
 *
 */
public class ICEAttackerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    public ICEAttackerTest() {
    }

    /**
     * Test of attack method, of class ICEAttacker.
     */
    @Test()
    @Category(SlowTests.class)
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
