/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.file;

import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class FileUtilsTest {

    @Test
    public void testIsFileExists() throws IOException {
        File file = new File("fileUtils.test.file");
        assert file.exists() || file.createNewFile();
        assertTrue(FileUtils.isFileExists(file.getAbsolutePath()));
        assert file.delete();
    }
}