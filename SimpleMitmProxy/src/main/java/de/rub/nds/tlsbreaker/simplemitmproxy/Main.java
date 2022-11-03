/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.simplemitmproxy;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;
import static org.apache.commons.lang3.StringUtils.trim;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Scanner;

import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CertificateDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.simplemitmproxy.config.SimpleMitmProxyCommandConfig;
import de.rub.nds.tlsbreaker.simplemitmproxy.impl.SimpleMitmProxy;
import de.rub.nds.tlsbreaker.simplemitmproxy.util.CertificateGenerator;
import de.rub.nds.tlsbreaker.simplemitmproxy.util.DerEncode;

public class Main {
    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        SimpleMitmProxyCommandConfig simpleMITMProxy = new SimpleMitmProxyCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(simpleMITMProxy).build();
        try {
            jc.parse(args);
        } catch (ParameterException ex) {
            ex.usage();
            return;
        }

        if (generalDelegate.isHelp()) {
            jc.usage();
            return;
        }

        if (!simpleMITMProxy.isNoCert()) {
            if (simpleMITMProxy.getDelegate(CertificateDelegate.class).getCertificate() == null) {
                Scanner sc = new Scanner(System.in);

                CONSOLE.info(
                    "No certificate was given! Should we generate a self signed certificate for you? (Y/y - Yes, Enter - Continue)");
                String userInput = trim(sc.nextLine());

                if ("Y".equals(userInput) || "y".equals(userInput)) {
                    // Generate certificate
                    KeyPairGenerator keyPairGenerator = null;
                    try {
                        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
                    } catch (NoSuchAlgorithmException e1) {
                        // TODO Auto-generated catch block
                        e1.printStackTrace();
                    }
                    keyPairGenerator.initialize(4096);
                    KeyPair keyPair = keyPairGenerator.generateKeyPair();

                    X509Certificate cert = null;

                    try {
                        cert = CertificateGenerator.generate(keyPair, "SHA256withRSA", "localhost", 730);
                    } catch (OperatorCreationException | CertificateException | CertIOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }

                    DerEncode encoder = new DerEncode();

                    String certeficateFileName = "self_signed_cert.pem";
                    encoder.encodeCertificateAndWrite(cert, certeficateFileName);

                    String keyFileName = "self_signed_key.pem";
                    encoder.encodePrivateKeyAndWrite(keyPair, keyFileName);

                    simpleMITMProxy.getDelegate(CertificateDelegate.class).setCertificate(certeficateFileName);
                    simpleMITMProxy.getDelegate(CertificateDelegate.class).setKey(keyFileName);

                } else {
                    CONSOLE.info("Continuing without a certificate!");
                }
            }
        }

        Attacker<?> attacker = new SimpleMitmProxy(simpleMITMProxy, simpleMITMProxy.createConfig());
        attacker.run();
    }
}
