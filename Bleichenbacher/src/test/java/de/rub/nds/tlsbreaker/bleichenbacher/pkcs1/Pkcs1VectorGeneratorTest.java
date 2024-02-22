/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.bleichenbacher.pkcs1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsbreaker.bleichenbacher.config.BleichenbacherCommandConfig;
import java.util.List;
import org.junit.jupiter.api.Test;

public class Pkcs1VectorGeneratorTest {

    /** Test of generatePlainPkcs1Vectors method, of class Pkcs1VectorGenerator. */
    @Test
    public void testGeneratePlainPkcs1Vectors() {
        List<Pkcs1Vector> vectors =
                Pkcs1VectorGenerator.generatePlainPkcs1Vectors(
                        2048, BleichenbacherCommandConfig.Type.FAST, ProtocolVersion.TLS12);
        assertNotNull(vectors);
        assertEquals(12, vectors.size(), "Expected number of PKCS#1 vectors should be generated");
    }
}
