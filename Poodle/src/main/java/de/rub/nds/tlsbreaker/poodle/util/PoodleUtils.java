/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.poodle.util;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.beust.jcommander.internal.Console;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

public class PoodleUtils {
    private static final Logger LOGGER = LogManager.getLogger();

    public byte[] replacePaddingWithBlock(byte[] input_byte, int block_size, int block_position) {

        byte[] modified_bytes = input_byte;

        if (input_byte.length % block_size != 0) {
            CONSOLE.warn("Returning the message unmodified! Byte array not multiple of block size. Block size: "+block_size);
        } else {
            try {
                System.arraycopy(modified_bytes, block_position * block_size, modified_bytes,
                        input_byte.length - block_size, block_size);
            } catch (Exception e) {
                CONSOLE.warn("Invalid arguments! Can not perform the operation for given block size and byte array!");
            }
        }
        return modified_bytes;
    }

}
