/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.util.file;

import junit.framework.TestCase;

import java.io.File;

public class FileUtilsTest extends TestCase {

    public void testIsFileExists() {
        File file = new File("./src/test/java/de/rub/nds/tlsbreaker/breakercommons/util/sample.pcapng");

        assertEquals(FileUtils.isFileExists(file.getAbsolutePath()), true);
    }
}