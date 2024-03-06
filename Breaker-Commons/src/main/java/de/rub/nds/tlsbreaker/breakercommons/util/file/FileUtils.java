/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.util.file;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;

public class FileUtils {

    public static boolean isFileExists(String filePath) {
        Path path = Paths.get(filePath);
        return Files.exists(path);
    }

    public static ArrayList<byte[]> readHexStringContentFromFile(String filePath) {
        if (!isFileExists(filePath)) {
            throw new UnsupportedOperationException("The file '" + filePath + "' does not exists.");
        }

        FileReader fileReader;
        try {
            fileReader = new FileReader(filePath);
        } catch (FileNotFoundException e) {
            throw new ConfigurationException("File not found");
        }

        BufferedReader bufferedReader = new BufferedReader(fileReader);
        ArrayList<byte[]> data = new ArrayList<byte[]>();
        String line;
        try {
            while ((line = bufferedReader.readLine()) != null) {
                byte[] bytes = ArrayConverter.hexStringToByteArray(line);
                data.add(bytes);
            }
            bufferedReader.close();
            fileReader.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return data;
    }
}
