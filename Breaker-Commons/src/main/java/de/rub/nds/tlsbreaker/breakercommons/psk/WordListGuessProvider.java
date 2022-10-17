/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.psk;

import de.rub.nds.tlsbreaker.breakercommons.psk.GuessProviderType;
import de.rub.nds.tlsbreaker.breakercommons.psk.GuessProvider;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

/**
 * A GuessProvider based on a WordList. It reads bytes from the input stream until a newline character is found. If the
 * InputStream does not contain anymore lines. Null is returned.
 */
public class WordListGuessProvider extends GuessProvider {

    private final BufferedReader bufferedReader;

    /**
     * Constructor
     *
     * @param stream
     *               An Input stream to read Guesses from
     */
    public WordListGuessProvider(InputStream stream) {
        super(GuessProviderType.WORDLIST);
        bufferedReader = new BufferedReader(new InputStreamReader(stream));
    }

    /**
     * Returns the next word from the input stream. If no more words are in the in InputStream null is returned.
     *
     * @return The next word from the input stream. If no more words are in the in InputStream null is returned.
     */
    @Override
    public byte[] getGuess() {
        try {
            String line = bufferedReader.readLine();
            if (line == null) {
                return null;
            }
            return ArrayConverter.hexStringToByteArray(line);
        } catch (IllegalArgumentException ie) {
            CONSOLE.warn("Incorrect HexaDecimal value is provided in the wordlist, Please provide correct value");
            CONSOLE.info(ie);
            return null;
        } catch (IOException ex) {
            return null;
        }
    }
}
