package de.rub.nds.tlsbreaker.poodle.util;

/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */


import org.junit.Test;

public class PoodleUtilsTest {


    public PoodleUtilsTest() {
    }

    @Test
    public void testReplacePaddingWithBlock(){

        byte[] original_bytes = new String("12345678abcdefgh").getBytes();

        PoodleUtils utils = new PoodleUtils();

        byte[] modified_bytes = utils.replacePaddingWithBlock(original_bytes, 4, 2);

        System.out.println(new String(modified_bytes));

        
    }

}
