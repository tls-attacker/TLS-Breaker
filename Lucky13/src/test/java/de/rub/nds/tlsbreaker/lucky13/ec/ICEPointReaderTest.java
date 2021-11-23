/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.lucky13.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import java.util.List;
import static org.junit.Assert.assertEquals;
import org.junit.Test;

/**
 *
 *
 */
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
