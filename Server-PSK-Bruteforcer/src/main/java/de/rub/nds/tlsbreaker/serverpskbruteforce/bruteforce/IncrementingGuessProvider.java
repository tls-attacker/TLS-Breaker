/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.serverpskbruteforce.bruteforce;

/**
 * An IncrementingGuessProvider is a GuessProvider which tries all byte[] sequences in a growing order. Starting by an
 * empty byte[] and then continuing the sequence with th byte[] size increased by 1. It would then try 00, 01, 02, ...,
 * FF and continue with 00 00, 00 01, 00 02 , ... to FF, FF and so on.
 */
public class IncrementingGuessProvider extends GuessProvider {

    private byte[] lastGuess = null;

    private int size = 0;

    /**
     * Default Constructor
     */
    public IncrementingGuessProvider() {
        super(GuessProviderType.INCREMENTING);
    }

    /**
     * Returns the last Guess incremented by 1.
     *
     * @return
     */
    @Override
    public byte[] getGuess() {
        byte[] guess = getIncrementedGuess();
        return guess;
    }

    private byte[] getIncrementedGuess() {
        if (lastGuess == null) {
            lastGuess = new byte[size];
        } else {
            lastGuess = createdIncrementedAtPosition(lastGuess, 0);
            if (lastGuess == null) {
                size++;
                lastGuess = new byte[size];
            }
        }
        return lastGuess;
    }

    private byte[] createdIncrementedAtPosition(byte[] array, int position) {
        if (array.length > position) {
            array[position] = (byte) (array[position] + 1);
            if (array[position] == 0) {
                return createdIncrementedAtPosition(array, position + 1);
            }
            return array;
        } else {
            return null;
        }
    }
}
