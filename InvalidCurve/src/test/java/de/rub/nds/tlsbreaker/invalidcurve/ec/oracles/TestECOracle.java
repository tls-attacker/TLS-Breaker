/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.invalidcurve.ec.oracles;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsbreaker.invalidcurve.ec.ICEPoint;
import java.math.BigInteger;
import java.util.Random;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class TestECOracle extends ECOracle {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SimpleDoubleAndAddComputer computer;

    public TestECOracle(NamedGroup namedCurve) {
        curve = CurveFactory.getCurve(namedCurve);
        BigInteger privateKey = new BigInteger(curve.getModulus().bitLength(), new Random());
        computer = new SimpleDoubleAndAddComputer((EllipticCurveOverFp) curve, privateKey);
    }

    @Override
    public boolean checkSecretCorrectness(Point ecPoint, BigInteger guessedSecret) {
        numberOfQueries++;
        if (numberOfQueries % 100 == 0) {
            LOGGER.debug("Number of queries so far: {}", numberOfQueries);
        }

        Point result;
        try {
            result = computer.mul(ecPoint, true);
        } catch (ArithmeticException ex) {
            result = new Point();
        }

        if (result.isAtInfinity()) {
            return false;
        } else {
            if (result.getFieldX().getData().compareTo(guessedSecret) == 0) {
                int order = ((ICEPoint) ecPoint).getOrder();
                BigInteger res = computer.getPrivateKey().mod(BigInteger.valueOf(order));
                LOGGER.debug("Ground truth: x = +/- " + res + " mod " + order);
                LOGGER.debug("Guessed x coordinate: " + guessedSecret);

                return true;
            } else {
                return false;
            }
        }
    }

    @Override
    public boolean isFinalSolutionCorrect(BigInteger guessedSecret) {
        return (guessedSecret.compareTo(computer.getPrivateKey()) == 0);
    }

    public BigInteger getPrivateKey() {
        return computer.getPrivateKey();
    }
}
