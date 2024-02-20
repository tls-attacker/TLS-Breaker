/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.exception;

/** */
public class AttackFailedException extends RuntimeException {

    /** */
    public AttackFailedException() {}

    /**
     * @param message
     */
    public AttackFailedException(String message) {
        super(message);
    }

    /**
     * @param message
     * @param cause
     */
    public AttackFailedException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * @param cause
     */
    public AttackFailedException(Throwable cause) {
        super(cause);
    }

    /**
     * @param message
     * @param cause
     * @param enableSuppression
     * @param writableStackTrace
     */
    public AttackFailedException(
            String message,
            Throwable cause,
            boolean enableSuppression,
            boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
