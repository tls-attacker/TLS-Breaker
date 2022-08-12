/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer.bruteforce;

import java.io.InputStream;

/**
 * A Factory class for GuessProvider instances, which creates GuessProvider objects based on a GuessProviderType.
 */
public class GuessProviderFactory {

    /**
     * Creates GuessProvider objects based on a GuessProviderType. Some GuessProvider require an InputSource to create
     * their guesses. If the GuessProvider does not use an InputStream, the InputStream is ignored
     *
     * @param  type
     *                     Type of the GuessProvider which should be created
     * @param  guessSource
     *                     An InputStream as an input source for the GuessProvider. If the GuessProvider does not use an
     *                     InputStream the guessSource is ignored.
     * @return             A new GuessProvider object.
     */
    public static GuessProvider createGuessProvider(GuessProviderType type, InputStream guessSource) {
        switch (type) {
            case INCREMENTING:
                return new IncrementingGuessProvider();
            case WORDLIST:
                return new WordListGuessProvider(guessSource);
            default:
                throw new UnsupportedOperationException("Guess provider \"" + type + "\" is not supported");
        }
    }

    private GuessProviderFactory() {
    }
}
