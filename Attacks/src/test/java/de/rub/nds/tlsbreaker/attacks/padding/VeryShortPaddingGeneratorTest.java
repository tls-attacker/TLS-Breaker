/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.padding;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsbreaker.attacks.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

public class VeryShortPaddingGeneratorTest {

    private VeryShortPaddingGenerator generator;

    @BeforeEach
    public void setUp() {
        generator = new VeryShortPaddingGenerator();
    }

    @Test
    public void testGetVectors() {
        for (CipherSuite suite : CipherSuite.getImplemented()) {
            if (suite.isCBC()) {
                List<PaddingVector> vectors = generator.getVectors(suite, ProtocolVersion.TLS12);
                for (PaddingVector vector : vectors) {
                    int length = vector.getRecordLength(suite, ProtocolVersion.TLS12, 4);
                    assertEquals(ShortPaddingGenerator.DEFAULT_CIPHERTEXT_LENGTH, length,
                        "We only create vectors of the same length to omit false positives");
                }
            }
        }
    }
}
