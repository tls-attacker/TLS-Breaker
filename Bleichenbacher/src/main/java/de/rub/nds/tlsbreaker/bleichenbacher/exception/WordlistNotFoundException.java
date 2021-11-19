/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.exception;

/**
 *
 */
public class WordlistNotFoundException extends RuntimeException {

    /**
     *
     */
    public WordlistNotFoundException() {
    }

    /**
     *
     * @param string
     */
    public WordlistNotFoundException(String string) {
        super(string);
    }

    /**
     *
     * @param string
     * @param throwable
     */
    public WordlistNotFoundException(String string, Throwable throwable) {
        super(string, throwable);
    }

    /**
     *
     * @param throwable
     */
    public WordlistNotFoundException(Throwable throwable) {
        super(throwable);
    }

    /**
     *
     * @param string
     * @param throwable
     * @param bln
     * @param bln1
     */
    public WordlistNotFoundException(String string, Throwable throwable, boolean bln, boolean bln1) {
        super(string, throwable, bln, bln1);
    }

}
