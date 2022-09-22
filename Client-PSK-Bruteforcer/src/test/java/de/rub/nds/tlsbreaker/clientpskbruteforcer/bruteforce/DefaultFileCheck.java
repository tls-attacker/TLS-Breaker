/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer.bruteforce;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import java.io.File;

import static org.junit.Assert.assertTrue;

/*
 * THIS TEST CHECKS THE PRESENCE OF DEFAULT FILE CONTAINING PSK VALUE, WHICH IS USED WHEN USER SELECTS 'DEFAULT' OPTION.
 */
public class DefaultFileCheck {

    private File FileLocation;

    public DefaultFileCheck() {
        FileLocation = new File("src" + File.separator + "main" + File.separator + "resources" + File.separator
            + "psk_common_passwords.txt" + File.separator);
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Test
    public void testDefaultPskFileExist() {
        File tempFile = new File(String.valueOf(FileLocation));
        boolean exists = tempFile.exists();
        assertTrue("Default File Containing PSk value is Missing : " + FileLocation, exists);

    }
}
