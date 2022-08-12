/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.serverpskbruteforce.bruteforce;

import org.junit.jupiter.api.Test;

public class IncrementingGuessProviderTest {

    /**
     * Test of getGuess method, of class IncrementingGuessProvider.
     */
    @Test
    public void testGetGuess() {
        IncrementingGuessProvider provider = new IncrementingGuessProvider();
        for (int i = 0; i < 2048; i++) {
            provider.getGuess();
        }
    }
}
