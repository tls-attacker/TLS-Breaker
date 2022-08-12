/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.ec.oracles;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.math.BigInteger;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TestECOracle extends ECOracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final BigInteger privateKey;

    /**
     *
     * @param namedCurve
     */
    public TestECOracle(NamedGroup namedCurve) {
        curve = CurveFactory.getCurve(namedCurve);
        privateKey = new BigInteger(curve.getModulus().bitLength(), new Random());
    }

    @Override
    public boolean checkSecretCorrectness(Point ecPoint, BigInteger guessedSecret) {
        numberOfQueries++;
        if (numberOfQueries % 100 == 0) {
            LOGGER.debug("Number of queries so far: {}", numberOfQueries);
        }
        Point result = curve.mult(guessedSecret, ecPoint);

        if (result.isAtInfinity()) {
            return false;
        } else {
            return (result.getFieldX().getData().compareTo(guessedSecret) == 0);
        }
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
        return guessedSecret.equals(privateKey);
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }
}
