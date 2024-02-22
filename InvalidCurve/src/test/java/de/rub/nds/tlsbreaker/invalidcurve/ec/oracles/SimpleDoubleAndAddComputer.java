/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.invalidcurve.ec.oracles;

import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.math.BigInteger;

/**
 * Simple EC computer with the double and add method and with the checks for infinity problems. The
 * reason it is included here is that the current EC computation in our TLS-core behaves similarly
 * as in JSSE and its optimizations return wrong results when working with invalid points with a
 * small order.
 *
 * <p>This EC computer should present a simple computation of the double and add method as was
 * assumed in the original paper of Jager et al.
 */
public class SimpleDoubleAndAddComputer {

    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    /** curve with its parameters */
    private final EllipticCurveOverFp curve;
    /** secret we use to multiply a given point */
    private final BigInteger privateKey;

    public SimpleDoubleAndAddComputer(EllipticCurveOverFp c, BigInteger privateKey) {
        this.curve = c;
        this.privateKey = privateKey;
    }

    /**
     * Doubles point, does not check for infinity
     *
     * @param p The point to double
     * @return The doubled point
     */
    public Point dbl(Point p) throws ArithmeticException {

        BigInteger x = p.getFieldX().getData();
        BigInteger y = p.getFieldY().getData();

        if (y.equals(BigInteger.ZERO)) {
            throw new ArithmeticException("y was equal to zero");
        }

        BigInteger l1 = ((THREE.multiply(x.pow(2))).add(curve.getFieldA().getData()));
        BigInteger l2 = TWO.multiply(y).modInverse(curve.getModulus());
        BigInteger l = l1.multiply(l2).mod(curve.getModulus());

        BigInteger xr = l.pow(2).subtract(TWO.multiply(x)).mod(curve.getModulus());
        BigInteger yr = l.multiply(x.subtract(xr)).subtract(y).mod(curve.getModulus());
        Point ret = curve.getPoint(xr, yr);
        return ret;
    }

    /**
     * Doubles point, checks for infinity if checkInfinity set
     *
     * @param p The point to double
     * @param checkInfinity If we should check for infinity
     * @return the Doubled point
     */
    public Point dbl(Point p, boolean checkInfinity) throws ArithmeticException {
        if (checkInfinity) {
            if (p.isAtInfinity()) {
                return p;
            }
            if (p.getFieldY().getData().signum() == 0) {
                return new Point();
            }
        }
        return dbl(p);
    }

    /**
     * Provides point addition, without infinity check
     *
     * @param p The point p to add
     * @param q The point q to add
     * @return The result of the addition
     */
    public Point add(Point p, Point q) throws ArithmeticException {
        BigInteger xp = p.getFieldX().getData();
        BigInteger yp = p.getFieldY().getData();
        BigInteger xq = q.getFieldX().getData();
        BigInteger yq = q.getFieldY().getData();

        if (xq.subtract(xp).mod(curve.getModulus()).equals(BigInteger.ZERO)) {
            throw new ArithmeticException("xq was equal to xp (mod p)");
        }

        BigInteger l =
                ((yq.subtract(yp)).multiply((xq.subtract(xp)).modInverse(curve.getModulus())))
                        .mod(curve.getModulus());
        BigInteger xr = l.pow(2).subtract(xp).subtract(xq).mod(curve.getModulus());
        BigInteger yr = (l.multiply(xp.subtract(xr))).subtract(yp).mod(curve.getModulus());
        Point ret = curve.getPoint(xr, yr);
        return ret;
    }

    /**
     * Provides point addition, checks for infinity in case checkInfinity is set
     *
     * @param p The point p to add
     * @param q The point q to add
     * @param checkInfinity If we should check for infinity
     * @return The result of the addition
     */
    public Point add(Point p, Point q, boolean checkInfinity) {
        if (checkInfinity) {
            if (p == null || p.isAtInfinity()) {
                return q;
            }
            if (q == null || q.isAtInfinity()) {
                return p;
            }

            if (p.getFieldX().getData().equals(q.getFieldX().getData())) {
                if (p.getFieldY().getData().equals(q.getFieldY().getData())) {
                    return dbl(p, true);
                } else {
                    return new Point();
                }
            }
        }
        return add(p, q);
    }

    /**
     * Simple point multiplication
     *
     * @param p The Point p to multiply
     * @param checkInfinity If we should check for infinity
     * @return The result of the multiplication
     */
    public Point mul(Point p, boolean checkInfinity) {

        Point r = curve.getPoint(p.getFieldX().getData(), p.getFieldY().getData());
        for (int i = 1; i < privateKey.bitLength(); i++) {
            r = dbl(r, checkInfinity);
            if (privateKey.testBit(privateKey.bitLength() - 1 - i)) {
                r = add(r, p, checkInfinity);
            }
        }
        return r;
    }

    public BigInteger getPrivateKey() {
        return privateKey;
    }
}
