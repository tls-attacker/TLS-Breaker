/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.psk;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.util.tests.TestCategories;
import de.rub.nds.tlsbreaker.breakercommons.psk.config.PskBruteForcerAttackCommonCommandConfig;
import de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider.GuessProviderType;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

/** This test checks whether the default file containing psk values can be read. */
public class DefaultPskFileIT {
    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testDefaultPskFileExists() {
        // this test could be removed
        File defaultPskFile = new File("src/main/resources/psk_common_passwords.txt");
        assertTrue(
                defaultPskFile.exists(),
                "Default dictionary containing common psk keys is missing: "
                        + defaultPskFile.getAbsolutePath());
    }

    @Test
    @Tag(TestCategories.INTEGRATION_TEST)
    public void testDefaultPskFileReadable() throws IOException {
        class AttackerConfig extends PskBruteForcerAttackCommonCommandConfig {
            protected AttackerConfig() {
                super(new GeneralDelegate());
            }
        }
        AttackerConfig config = new AttackerConfig();
        config.setGuessProviderType(GuessProviderType.WORDLIST);
        config.setGuessProviderInputFile(null);

        var stream = config.getGuessProviderInputStream();
        BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(stream));

        assertNotNull(bufferedReader.readLine(), "Could not read line");
        stream.close();
    }
}
