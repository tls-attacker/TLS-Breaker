/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.ec.oracles;

import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

/**
 *
 */
public abstract class ECOracle {

    /**
     * logger
     */
    private static final Logger LOGGER = LogManager.getLogger();

    /*
     * number of queries issued to oracle
     */
    protected long numberOfQueries;

    /**
     * curve used by the oracle
     */
    protected EllipticCurve curve;

    /**
     * Takes an ec point and a guessed secret and returns true, in case the secret was guessed correctly.
     *
     * @param  ecPoint
     *                       The Point
     * @param  guessedSecret
     *                       The guessed Secret
     * @return               True if the secret is guessed correctly
     */
    public abstract boolean checkSecretCorrectness(Point ecPoint, BigInteger guessedSecret);

    /**
     * Sends the oracle a request with a guessed secret key resulting from the attack. The oracle responds with true, in
     * case the guessed key was correct.
     *
     * @param  guessedSecret
     *                       The guessed Secret
     * @return               True if the Solution is correct
     */
    public abstract boolean isFinalSolutionCorrect(BigInteger guessedSecret);

    /**
     *
     * @return
     */
    public long getNumberOfQueries() {
        return numberOfQueries;
    }

    /**
     *
     * @param numberOfQueries
     */
    public void setNumberOfQueries(long numberOfQueries) {
        this.numberOfQueries = numberOfQueries;
    }

    /**
     *
     * @return
     */
    public EllipticCurve getCurve() {
        return curve;
    }

    /**
     *
     * @param curve
     */
    public void setCurve(EllipticCurve curve) {
        this.curve = curve;
    }
}
