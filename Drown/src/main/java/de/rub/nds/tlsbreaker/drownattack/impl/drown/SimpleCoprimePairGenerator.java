/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.drownattack.impl.drown;

import java.math.BigInteger;

class SimpleCoprimePairGenerator extends CoprimePairGenerator {

    private long nextU = 1;
    private long maxQueries;

    public SimpleCoprimePairGenerator(long maxQueries) {
        super();
        this.maxQueries = maxQueries;
    }

    @Override
    public BigInteger[] next() {
        // TODO: Intuitively, neighboring number should always be coprime, but
        // is that really the case?
        long t = nextU + 1;
        BigInteger[] pair = {BigInteger.valueOf(nextU), BigInteger.valueOf(t)};

        numberOfQueries++;
        nextU += 2;

        return pair;
    }

    @Override
    public boolean hasNext() {
        return numberOfQueries < maxQueries;
    }
}
