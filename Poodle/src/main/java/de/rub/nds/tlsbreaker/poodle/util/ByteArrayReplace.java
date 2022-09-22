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

public class ByteArrayReplace {
    private static final Logger LOGGER = LogManager.getLogger();

    public byte[] byteArrayCopyAndReplace(byte[] input_byte, int block_count) {
        boolean empty_byte_array = true;
        byte[] byte_array = input_byte;
        byte[] replace_text = new byte[8];

        for (byte b : byte_array) {
            if (b != 0) {
                empty_byte_array = false;
                break;
            }
        }

        if (empty_byte_array) {
            System.out.println("byte Array is Empty");
            return null;
        } else if (byte_array.length < 8) {
            System.out.println("byte Array size is too less");
            return null;
        } else if (block_count <= 0) {
            System.out.println("Inappropriate Block Size:" + block_count);
            return null;
        }
//        System.out.println("byte Array is not Empty");

        int block_to_start = (block_count - 1) * 8;
        if (block_to_start > (byte_array.length - 1)) {
            System.out.println("Please provide the Block size present within the byte array");
            return null;
        }
        int block_end = block_to_start + 8;
        int j = 0;
        int len_arr = byte_array.length;

        try {
            for (int i = block_to_start; i < block_end; i++) {
                replace_text[j] = byte_array[i];
                j = j + 1;
            }
        } catch (Exception ex) {
            LOGGER.warn("Issue with Byte array replacing", ex);
            return null;
        }

        System.arraycopy(replace_text, 0, byte_array, len_arr - 8, 8);

        return byte_array;
    }
}
