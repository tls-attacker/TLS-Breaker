/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.bleichenbacher.pkcs1;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsbreaker.bleichenbacher.pkcs1.oracles.StdPlainPkcs1Oracle;
import de.rub.nds.tlsbreaker.bleichenbacher.pkcs1.oracles.TestPkcs1Oracle;
import de.rub.nds.tlsbreaker.breakercommons.cca.Pkcs1Oracle;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

public class BleichenbacherOracleTest {

    @Test
    public void testJSSEOracle() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        Pkcs1Oracle oracle =
                new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.JSSE, 128);

        byte[] msg = new byte[127];
        Arrays.fill(msg, (byte) 0x01);
        // start with 0x02, no 0x00 byte given
        msg[0] = 0x02;

        assertFalse(oracle.checkPKCSConformity(msg));

        // set the second last byte to 0x00
        msg[msg.length - 2] = 0x00;
        assertTrue(oracle.checkPKCSConformity(msg));

        // insert an extra 0x00 byte in the middle
        msg[20] = 0x00;
        assertFalse(oracle.checkPKCSConformity(msg));
    }

    @Test
    public void testXMLENCOracle() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        Pkcs1Oracle oracle =
                new StdPlainPkcs1Oracle(
                        keyPair.getPublic(), TestPkcs1Oracle.OracleType.XMLENC, 128);

        byte[] msg = new byte[127];
        Arrays.fill(msg, (byte) 0x01);
        // start with 0x02, no 0x00 byte given
        msg[0] = 0x02;

        assertFalse(oracle.checkPKCSConformity(msg));

        // set the 17th byte from behind to 0x00
        msg[msg.length - 17] = 0x00;
        assertTrue(oracle.checkPKCSConformity(msg));

        // set the 25th byte from behind to 0x00
        msg[msg.length - 25] = 0x00;
        assertTrue(oracle.checkPKCSConformity(msg));

        // set the 33th byte from behind to 0x00
        msg[msg.length - 33] = 0x00;
        assertTrue(oracle.checkPKCSConformity(msg));

        msg[34] = 0x00;
        assertFalse(oracle.checkPKCSConformity(msg));

        // insert an extra 0x00 byte in the middle
        msg[50] = 0x00;
        assertFalse(oracle.checkPKCSConformity(msg));
    }
}
