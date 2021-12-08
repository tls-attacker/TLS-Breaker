/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.exception;

/**
 *
 */
public class OracleUnstableException extends RuntimeException {

    /**
     *
     * @param string
     */
    public OracleUnstableException(String string) {
        super(string);
    }

}