/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.bleichenbacher.pkcs1;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsbreaker.bleichenbacher.pkcs1.oracles.StdPlainPkcs1Oracle;
import de.rub.nds.tlsbreaker.bleichenbacher.pkcs1.oracles.TestPkcs1Oracle;
import de.rub.nds.tlsbreaker.breakercommons.cca.Pkcs1Oracle;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Random;
import javax.crypto.Cipher;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

public class MangerAttackPlaintextTest {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final int PREMASTER_SECRET_LENGTH = 48;

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testMangerAttack() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        Random sr = new Random();
        byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
        sr.nextBytes(plainBytes);
        byte[] cipherBytes;

        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        cipherBytes = cipher.doFinal(plainBytes);

        cipher = Cipher.getInstance("RSA/None/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] message = cipher.doFinal(cipherBytes);

        Pkcs1Oracle oracle =
                new StdPlainPkcs1Oracle(
                        keyPair.getPublic(),
                        TestPkcs1Oracle.OracleType.MANGER_0x00,
                        cipher.getBlockSize());

        // we are handling plaintexts, so we insert raw message there
        Manger attacker = new Manger(message, oracle);
        attacker.attack();
        BigInteger solution = attacker.getSolution();

        assertArrayEquals(
                message,
                solution.toByteArray(),
                "The computed solution for Manger attack must be equal to the original message");

        // test with a message not starting with 0x00
        message = ArrayConverter.concatenate(new byte[] {1}, message);
        LOGGER.debug(ArrayConverter.bytesToHexString(message));
        attacker = new Manger(message, oracle);
        attacker.attack();
        solution = attacker.getSolution();

        assertArrayEquals(
                message,
                solution.toByteArray(),
                "The computed solution for Manger attack must be equal to the original message");
    }

    @Test
    @Disabled("Manual execution only, may take several minutes to complete")
    public void testMangerAttackPerformance() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        List<Long> queries = new LinkedList<>();

        for (int i = 0; i < 100; i++) {
            Random sr = new Random();
            byte[] plainBytes = new byte[PREMASTER_SECRET_LENGTH];
            sr.nextBytes(plainBytes);
            byte[] cipherBytes;

            Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            cipherBytes = cipher.doFinal(plainBytes);

            cipher = Cipher.getInstance("RSA/None/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            byte[] message = cipher.doFinal(cipherBytes);

            Pkcs1Oracle oracle =
                    new StdPlainPkcs1Oracle(
                            keyPair.getPublic(),
                            TestPkcs1Oracle.OracleType.MANGER_0x00,
                            cipher.getBlockSize());

            // we are handling plaintexts, so we insert raw message there
            Manger attacker = new Manger(message, oracle);
            attacker.attack();
            BigInteger solution = attacker.getSolution();

            assertArrayEquals(
                    message,
                    solution.toByteArray(),
                    "The computed solution for Manger attack must be equal to the original message");

            queries.add(oracle.getNumberOfQueries());
        }

        Collections.sort(queries);
        LOGGER.debug(queries);
    }
}
