/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.paddingoracle.config;

/** */
public enum PaddingRecordGeneratorType {

    /** */
    VERY_SHORT,
    /** */
    SHORT,
    /** */
    MEDIUM,
    /** */
    LONG,

    LONG_RECORD
}
