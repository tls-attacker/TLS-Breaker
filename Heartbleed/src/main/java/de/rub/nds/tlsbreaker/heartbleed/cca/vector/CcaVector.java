/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.cca.vector;

import de.rub.nds.tlsbreaker.heartbleed.cca.CcaCertificateType;
import de.rub.nds.tlsbreaker.heartbleed.cca.CcaWorkflowType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;

/**
 *
 */
public class CcaVector {

    private final ProtocolVersion protocolVersion;
    private final CipherSuite cipherSuite;
    private final CcaWorkflowType ccaWorkflowType;
    private final CcaCertificateType ccaCertificateType;

    public CcaVector(ProtocolVersion protocolVersion, CipherSuite cipherSuite, CcaWorkflowType ccaWorkflowType,
        CcaCertificateType ccaCertificateType) {
        this.protocolVersion = protocolVersion;
        this.cipherSuite = cipherSuite;
        this.ccaWorkflowType = ccaWorkflowType;
        this.ccaCertificateType = ccaCertificateType;
    }

    public ProtocolVersion getProtocolVersion() {
        return protocolVersion;
    }

    public CipherSuite getCipherSuite() {
        return cipherSuite;
    }

    public CcaWorkflowType getCcaWorkflowType() {
        return ccaWorkflowType;
    }

    public CcaCertificateType getCcaCertificateType() {
        return ccaCertificateType;
    }

    @Override
    public String toString() {
        return "CcaTask{protocolVersion=" + protocolVersion + ", cipherSuite=" + cipherSuite + ", workflowType="
            + ccaWorkflowType + ", certificateType=" + ccaCertificateType + "}";
    }

}
