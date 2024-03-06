/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.invalidcurve.ec;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsbreaker.invalidcurve.ec.oracles.TestECOracle;
import java.math.BigInteger;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

public class ICEAttackerTest {

    private static final Logger LOGGER = LogManager.getLogger();

    /** Test attack using a faked JSSE server */
    @Test
    @Tag(TestCategories.SLOW_TEST)
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testAttackOnOracleJSSE() {
        CONSOLE.info(
                "Starting ICEAttacker test against an Oracle/JSSE mockup target... this may take some time");
        TestECOracle oracle = new TestECOracle(NamedGroup.SECP256R1);
        ICEAttacker attacker =
                new ICEAttacker(oracle, ICEAttacker.ServerType.ORACLE, 4, NamedGroup.SECP256R1);
        BigInteger result = attacker.attack();

        LOGGER.info("Private key computed in the attack: " + result);
        LOGGER.info("Server private key: " + oracle.getPrivateKey());

        assertEquals(oracle.getPrivateKey(), result);
    }

    /** Test attack using a normal server computation mistake. */
    @Test
    public void testAttackNormal() {
        CONSOLE.info(
                "Starting ICEAttacker test against a Bouncy Castle mockup target... this may take some time");
        TestECOracle oracle = new TestECOracle(NamedGroup.SECP256R1);
        ICEAttacker attacker =
                new ICEAttacker(oracle, ICEAttacker.ServerType.NORMAL, 0, NamedGroup.SECP256R1);
        BigInteger result = attacker.attack();

        LOGGER.debug("Private key computed in the attack: " + result);
        LOGGER.debug("Server private key: " + oracle.getPrivateKey());

        assertEquals(oracle.getPrivateKey(), result);
    }
}
