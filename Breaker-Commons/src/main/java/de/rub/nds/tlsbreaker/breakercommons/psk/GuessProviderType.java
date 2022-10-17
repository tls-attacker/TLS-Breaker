/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.psk;

/**
 * A Type of GuessProvider.
 */
public enum GuessProviderType {

    /**
     * An IncrementingGuessProvider just tries all byte[] sequences in order
     */
    INCREMENTING,
    /**
     * A WordListGuessProvider uses an InputSource to try all words from the InputSource
     */
    WORDLIST
}
