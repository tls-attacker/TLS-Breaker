/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.ec;

import static org.junit.jupiter.api.Assertions.assertEquals;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import org.junit.jupiter.api.Test;

import java.util.List;

public class ICEPointReaderTest {

    /**
     * Test of readPoints method, of class ICEPointReader.
     *
     * @throws java.lang.Exception
     */
    @Test
    public void testReadPoints() throws Exception {
        List<ICEPoint> result = ICEPointReader.readPoints(NamedGroup.SECP192R1);
        assertEquals(5, result.get(0).getOrder());
    }

}
