/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.padding;

import de.rub.nds.tlsbreaker.attacks.general.Vector;
import de.rub.nds.tlsbreaker.attacks.util.response.ResponseFingerprint;

public class VectorResponse {

    private final ResponseFingerprint fingerprint;

    private final Vector vector;

    private VectorResponse() {
        fingerprint = null;
        vector = null;
    }

    public VectorResponse(Vector vector, ResponseFingerprint fingerprint) {
        this.vector = vector;
        this.fingerprint = fingerprint;
    }

    public Vector getVector() {
        return vector;
    }

    public ResponseFingerprint getFingerprint() {
        return fingerprint;
    }

    @Override
    public String toString() {
        return "VectorResponse{" + "fingerprint=" + fingerprint + ", vector=" + vector + '}';
    }
}
