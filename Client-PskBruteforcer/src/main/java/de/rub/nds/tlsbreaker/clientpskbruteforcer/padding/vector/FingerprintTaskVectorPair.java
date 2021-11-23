/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer.padding.vector;

import de.rub.nds.tlsbreaker.clientpskbruteforcer.general.Vector;
import de.rub.nds.tlsbreaker.clientpskbruteforcer.task.FingerPrintTask;

public class FingerprintTaskVectorPair<T extends Vector> {

    private final FingerPrintTask fingerPrintTask;

    private final T vector;

    public FingerprintTaskVectorPair(FingerPrintTask fingerPrintTask, T vector) {
        this.fingerPrintTask = fingerPrintTask;
        this.vector = vector;
    }

    public FingerPrintTask getFingerPrintTask() {
        return fingerPrintTask;
    }

    public T getVector() {
        return vector;
    }

    @Override
    public String toString() {
        return "FingerprintTaskVectorPair{" + "fingerPrintTask=" + fingerPrintTask + ", vector=" + vector + '}';
    }

}
