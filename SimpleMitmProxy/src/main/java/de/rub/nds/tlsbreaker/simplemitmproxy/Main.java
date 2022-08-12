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

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Scanner;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.Base64;
import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.CertificateDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;
import de.rub.nds.tlsbreaker.simplemitmproxy.config.SimpleMitmProxyCommandConfig;
import de.rub.nds.tlsbreaker.simplemitmproxy.impl.CertificateGenerator;
import de.rub.nds.tlsbreaker.simplemitmproxy.impl.SimpleMitmProxy;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

/**
 *
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     * @param  args
     * @throws FileNotFoundException
     */
    public static void main(String[] args) throws FileNotFoundException {
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

                Base64 encoder = new Base64();
                String cert_begin = "-----BEGIN CERTIFICATE-----\n";
                String end_cert = "\n-----END CERTIFICATE-----";

                byte[] derCert = null;
                try {
                    derCert = cert.getEncoded();
                } catch (CertificateEncodingException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
                String pemCertPre = new String(encoder.encode(derCert));
                String pemCert = cert_begin + pemCertPre + end_cert;

                try (PrintStream out = new PrintStream(new FileOutputStream("self_signed_cert.pem"))) {
                    out.print(pemCert);
                }

                PrivateKey prv = keyPair.getPrivate();
                byte[] prvBytes = prv.getEncoded();

                String key_begin = "-----BEGIN PRIVATE KEY-----\n";
                String key_end = "\n-----END PRIVATE KEY-----";
                String privateKeyEncoded = new String(encoder.encode(prvBytes));
                String privateKey = key_begin + privateKeyEncoded + key_end;

                try (PrintStream out = new PrintStream(new FileOutputStream("self_signed_key.pem"))) {
                    out.print(privateKey);
                }

                simpleMITMProxy.getDelegate(CertificateDelegate.class).setCertificate("self_signed_cert.pem");
                simpleMITMProxy.getDelegate(CertificateDelegate.class).setKey("self_signed_key.pem");

            } else {
                CONSOLE.info("Continuing without a certificate!");
            }
        } else {
            // System.out.println("The certificate is given");
        }

        Attacker<? extends TLSDelegateConfig> attacker =
            new SimpleMitmProxy(simpleMITMProxy, simpleMITMProxy.createConfig());

        if (attacker.getConfig().isExecuteAttack()) {
            attacker.attack();
        } else {
            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                } else if (Objects.equals(result, Boolean.FALSE)) {
                    CONSOLE.info("Vulnerable:" + result.toString());
                } else {
                    CONSOLE.warn("Vulnerable: Uncertain");
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
    }
}
