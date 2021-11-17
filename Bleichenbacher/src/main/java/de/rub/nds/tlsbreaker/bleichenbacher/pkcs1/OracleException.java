/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on
							TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit
							GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher.pkcs1;

/**
 * @version 0.1
 */
public class OracleException extends RuntimeException {

    /**
     *
     */
    public OracleException() {

    }

    /**
     *
     * @param message
     */
    public OracleException(String message) {
        super(message);
    }

    /**
     *
     * @param message
     * @param t
     */
    public OracleException(String message, Throwable t) {
        super(message, t);
    }

}
