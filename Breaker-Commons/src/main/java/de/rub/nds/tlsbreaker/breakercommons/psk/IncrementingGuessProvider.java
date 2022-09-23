/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.psk;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.constants.Bits;

/**
 * An IncrementingGuessProvider is a GuessProvider which tries all byte[] sequences in a growing order. Starting by an
 * empty byte[] and then continuing the sequence with th byte[] size increased by 1. It would then try 00, 01, 02, ...,
 * FF and continue with 00 00, 00 01, 00 02 , ... to FF, FF and so on.
 */
public class IncrementingGuessProvider extends GuessProvider {

    private int ctr = 0;
    private int size = 0;

    /**
     * Default Constructor
     */
    public IncrementingGuessProvider() {
        super(GuessProviderType.INCREMENTING);
    }

    /**
     * Returns the last guess incremented by 1 (or resets guess to 0 increments byte size by one).
     */
    @Override
    public byte[] getGuess() {
        if (ctr == 0 && size == 0) {
            size = 1;
            return new byte[0];
        } else {
            byte[] nextGuess = ArrayConverter.intToBytes(ctr, size);
            ctr++;
            if (ctr == 1 << (Bits.IN_A_BYTE * size)) {
                // Iterated over all possible byte combinations of length <= size
                ctr = 0;
                size++;
            }
            return nextGuess;
        }
    }
}
