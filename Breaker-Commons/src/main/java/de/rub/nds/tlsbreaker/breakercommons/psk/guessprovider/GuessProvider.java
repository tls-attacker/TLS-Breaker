/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider;

import java.util.Iterator;
import java.util.NoSuchElementException;

/**
 * A GuessProvider is responsible for the creation of byte[] sequences for brute
 * force attacks. The guess provider
 * should minimize the number of guesses according to heuristics.
 */
public abstract class GuessProvider implements Iterator<byte[]> {

    private final GuessProviderType type;

    /**
     * Constructor
     *
     * @param type
     *             Type of the GuessProvider
     */
    protected GuessProvider(GuessProviderType type) {
        this.type = type;
    }

    /**
     * Returns the next guess for the attack. Guesses should not repeat, but it is
     * not completely prohibited by this
     * API. Returns null if no more guesses are available.
     *
     * @return The next byte[] to be used in the brute force attack.
     */
    public abstract byte[] getGuess();

    /**
     * Returns the type of this GuessProvider
     *
     * @return Type of this GuessProvider
     */
    public GuessProviderType getType() {
        return type;
    }

    private boolean hasFetchedNext = false;
    private byte[] fetchedNext = null;

    @Override
    public byte[] next() {
        if (!hasNext()) {
            throw new NoSuchElementException();
        }
        return fetchedNext;
    }

    @Override
    public boolean hasNext() {
        if (!hasFetchedNext) {
            fetchedNext = getGuess();
            hasFetchedNext = true;
        }
        return fetchedNext != null;
    }
}
