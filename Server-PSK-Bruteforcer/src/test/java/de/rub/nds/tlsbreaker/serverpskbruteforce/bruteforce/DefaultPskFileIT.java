/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.serverpskbruteforce.bruteforce;

import de.rub.nds.tlsattacker.util.tests.TestCategories;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This test checks the presence of default file containing psk value, which is used when user selects 'default' option.
 */
public class DefaultPskFileIT {
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testDefaultPskFileExists() {
        File defaultPskFile = new File("src/main/resources/psk_common_passwords.txt");
        assertTrue(defaultPskFile.exists(),
            "Default dictionary containing common psk keys is missing: " + defaultPskFile.getAbsolutePath());
    }
}
