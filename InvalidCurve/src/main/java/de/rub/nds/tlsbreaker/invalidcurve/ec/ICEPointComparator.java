/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.invalidcurve.ec;

import java.util.Comparator;

/** */
public class ICEPointComparator implements Comparator<ICEPoint> {

    /**
     * @param o1
     * @param o2
     * @return
     */
    @Override
    public int compare(ICEPoint o1, ICEPoint o2) {
        return Integer.compare(o1.getOrder(), o2.getOrder());
    }
}
