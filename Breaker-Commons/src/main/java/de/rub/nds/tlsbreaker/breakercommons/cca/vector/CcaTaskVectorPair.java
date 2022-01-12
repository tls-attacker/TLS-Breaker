/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons.cca.vector;

import de.rub.nds.tlsbreaker.breakercommons.task.CcaTask;

/**
 *
 */
public class CcaTaskVectorPair {

    private final CcaTask ccaTask;

    private final CcaVector ccaVector;

    public CcaTaskVectorPair(CcaTask ccaTask, CcaVector vector) {
        this.ccaTask = ccaTask;
        this.ccaVector = vector;
    }

    public CcaTask getCcaTask() {
        return ccaTask;
    }

    public CcaVector getVector() {
        return ccaVector;
    }

    @Override
    public String toString() {
        return "CcaProbeTaskVectorPair{" + "ccaTask=" + ccaTask + ", vector=" + ccaVector + '}';
    }

}
