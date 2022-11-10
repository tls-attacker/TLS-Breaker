/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.pkcs1;

import de.rub.nds.tlsbreaker.breakercommons.cca.Pkcs1Oracle;
import de.rub.nds.tlsbreaker.bleichenbacher.pkcs1.oracles.StdPlainPkcs1Oracle;
import de.rub.nds.tlsbreaker.bleichenbacher.pkcs1.oracles.TestPkcs1Oracle;
import de.rub.nds.tlsattacker.core.state.TlsContext;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

public class BleichenbacherAttackPlaintextTest {

    private static final int PREMASTER_SECRET_LENGTH = 48;

    private TlsContext context;

    @BeforeAll
    public static void setUpClass() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        context = new TlsContext();
    }

    @Test
    public void testBleichenbacherAttack() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        context.getBadSecureRandom().setSeed(0);
        keyPairGenerator.initialize(2048, context.getBadSecureRandom());
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        SecureRandom sr = new SecureRandom();
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
            new StdPlainPkcs1Oracle(keyPair.getPublic(), TestPkcs1Oracle.OracleType.TTT, cipher.getBlockSize());

        Bleichenbacher attacker = new Bleichenbacher(message, oracle, true);
        attacker.attack();
        BigInteger solution = attacker.getSolution();

        assertArrayEquals(message, solution.toByteArray(),
            "The computed solution for Bleichenbacher must be equal to the original message");
    }
}
