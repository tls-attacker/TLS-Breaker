/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.heartbleed.util.response;

/**
 *
 *
 */
public enum EqualityError {

    /**
     *
     */
    NONE,
    /**
     *
     */
    SOCKET_STATE,
    /**
     *
     */
    MESSAGE_COUNT,
    /**
     *
     */
    RECORD_COUNT,
    /**
     *
     */
    RECORD_CLASS,
    /**
     *
     */
    MESSAGE_CLASS,
    /**
     *
     */
    MESSAGE_CONTENT,
    /**
     *
     */
    RECORD_CONTENT_TYPE,
    /**
     *
     */
    RECORD_LENGTH,
    /**
     *
     */
    RECORD_VERSION,
    /**
     *
     */
    RECORD_CONTENT;

}
