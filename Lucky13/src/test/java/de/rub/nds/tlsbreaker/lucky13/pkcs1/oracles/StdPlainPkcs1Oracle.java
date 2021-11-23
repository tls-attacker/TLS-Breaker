/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.lucky13.pkcs1.oracles;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 *
 *
 */
public class StdPlainPkcs1Oracle extends TestPkcs1Oracle {

    public StdPlainPkcs1Oracle(final PublicKey pubKey, final TestPkcs1Oracle.OracleType oracleType,
        final int blockSize) {
        this.publicKey = (RSAPublicKey) pubKey;
        this.oracleType = oracleType;
        this.isPlaintextOracle = true;
        this.blockSize = blockSize;
    }

    /**
     *
     * @param  msg
     * @return
     */
    @Override
    public boolean checkPKCSConformity(final byte[] msg) {
        numberOfQueries++;
        return checkDecryptedBytes(msg);
    }
}
