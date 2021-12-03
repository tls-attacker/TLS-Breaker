/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.breakercommons.padding;

import de.rub.nds.tlsbreaker.breakercommons.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import java.util.List;

/**
 *
 *
 */
public abstract class PaddingVectorGenerator {

    /**
     *
     * @param  suite
     * @param  version
     * @return
     */
    public abstract List<PaddingVector> getVectors(CipherSuite suite, ProtocolVersion version);

    /**
     * Creates an array of (padding+1) padding bytes.
     *
     * Example for padding 03: [03 03 03 03]
     *
     * @param  padding
     * @return
     */
    protected final byte[] createPaddingBytes(int padding) {
        byte[] paddingBytes = new byte[padding + 1];
        for (int i = 0; i < paddingBytes.length; i++) {
            paddingBytes[i] = (byte) padding;
        }
        return paddingBytes;
    }
}
