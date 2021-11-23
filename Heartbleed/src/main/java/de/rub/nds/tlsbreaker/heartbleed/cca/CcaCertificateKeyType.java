/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.cca;

public enum CcaCertificateKeyType {
    RSA("rsa"),
    DH("dh"),
    DSA("dsa"),
    ECDSA("ecdsa");

    private String javaName;

    CcaCertificateKeyType(String javaName) {
        this.javaName = javaName;
    }

    public static CcaCertificateKeyType fromJavaName(String name) {
        for (CcaCertificateKeyType ccaCertificateKeyType : values()) {
            if (ccaCertificateKeyType.getJavaName().equals(name)) {
                return ccaCertificateKeyType;
            }
        }
        return null;
    }

    public String getJavaName() {
        return javaName;
    }

}
