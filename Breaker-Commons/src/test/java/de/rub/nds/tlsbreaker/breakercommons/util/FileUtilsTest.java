/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 * <p>
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util;

import junit.framework.TestCase;

import java.io.File;

public class FileUtilsTest extends TestCase {

    public void testIsFileExists() {
        File file = new File("./src/test/java/de/rub/nds/tlsbreaker/breakercommons/util/sample.pcapng");

        assertEquals(FileUtils.isFileExists(file.getAbsolutePath()), true);
    }
}