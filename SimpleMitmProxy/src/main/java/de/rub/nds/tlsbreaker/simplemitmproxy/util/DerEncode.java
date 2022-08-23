/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.simplemitmproxy.util;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import org.bouncycastle.util.encoders.Base64;
import java.security.KeyPair;
import java.security.PrivateKey;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

public class DerEncode {

    private static final Logger LOGGER = LogManager.getLogger();

    public String encodeCertificateAndWrite(X509Certificate inputCertificate, String fileName)
        throws FileNotFoundException {
        String cert_begin = "-----BEGIN CERTIFICATE-----\n";
        String end_cert = "\n-----END CERTIFICATE-----";

        byte[] derCert = null;
        try {
            derCert = inputCertificate.getEncoded();
        } catch (CertificateEncodingException e) {
            CONSOLE.error("Something went wrong");
        }
        String pemCertPre = new String(Base64.encode(derCert));
        String pemCert = cert_begin + pemCertPre + end_cert;

        try (PrintStream out = new PrintStream(new FileOutputStream(fileName))) {
            out.print(pemCert);
        }

        return pemCert;
    }

    public String encodePrivateKeyAndWrite(KeyPair keyPair, String fileName) throws FileNotFoundException {
        PrivateKey prv = keyPair.getPrivate();
        byte[] prvBytes = prv.getEncoded();

        String key_begin = "-----BEGIN PRIVATE KEY-----\n";
        String key_end = "\n-----END PRIVATE KEY-----";
        String privateKeyEncoded = new String(Base64.encode(prvBytes));
        String privateKey = key_begin + privateKeyEncoded + key_end;

        try (PrintStream out = new PrintStream(new FileOutputStream(fileName))) {
            out.print(privateKey);
        }

        return privateKey;
    }

}
