/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.serverpskbruteforce.impl.drown;

import java.math.BigInteger;
import java.util.Iterator;

/**
 * Base class for stateful generators which return pairs of coprime numbers for usage with Bleichenbacher "Trimmers" as
 * introduced by Bardou et al. 2012.
 */
abstract class CoprimePairGenerator implements Iterator<BigInteger[]> {

    protected long numberOfQueries = 0;

    public long getNumberOfQueries() {
        return numberOfQueries;
    }

}
