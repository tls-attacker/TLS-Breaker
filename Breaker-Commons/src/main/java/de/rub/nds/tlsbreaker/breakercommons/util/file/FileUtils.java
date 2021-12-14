/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 * <p>
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 * <p>
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.util.file;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtils {

    public static boolean isFileExists(String filePath) {
        Path path = Paths.get(filePath);
        return Files.exists(path);
    }
}
