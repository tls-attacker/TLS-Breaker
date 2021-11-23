/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.drownattack.pkcs1;

/**
 *
 *
 */
public enum BleichenbacherWorkflowType {

    /**
     *
     */
    CKE_CCS_FIN("Complete TLS protocol flow with CCS and Finished messages"),
    /**
     *
     */
    CKE("TLS protocol flow with missing CCS and Finished messages"),
    /**
     *
     */
    CKE_CCS("TLS protocol flow with missing Finished message"),
    /**
     *
     */
    CKE_FIN("TLS protocol flow with missing CCS message");

    String description;

    BleichenbacherWorkflowType(String description) {
        this.description = description;
    }

    /**
     *
     * @return
     */
    public String getDescription() {
        return description;
    }
}
