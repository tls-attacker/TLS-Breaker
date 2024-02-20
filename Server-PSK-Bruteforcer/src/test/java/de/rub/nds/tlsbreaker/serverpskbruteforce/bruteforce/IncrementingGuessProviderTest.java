/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.serverpskbruteforce.bruteforce;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider.IncrementingGuessProvider;
import org.junit.jupiter.api.Test;

public class IncrementingGuessProviderTest {

    /** Test of getGuess method, of class IncrementingGuessProvider. */
    @Test
    public void testGetGuess() {
        IncrementingGuessProvider provider = new IncrementingGuessProvider();
        int byteLength = 0;
        for (int i = 0; i < 2048; i++) {
            if (i == 1 << (8 * byteLength)) {
                byteLength++;
                i = 0;
            }
            byte[] expectedGuess =
                    byteLength == 0 ? new byte[0] : ArrayConverter.intToBytes(i, byteLength);
            byte[] actualGuess = provider.getGuess();
            assertArrayEquals(
                    expectedGuess,
                    actualGuess,
                    String.format(
                            "Incrementing guess provider returned 0x%s, but next guess should be 0x%s",
                            ArrayConverter.bytesToRawHexString(actualGuess),
                            ArrayConverter.bytesToRawHexString(expectedGuess)));
        }
    }
}
