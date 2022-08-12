/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.*;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsbreaker.attacks.config.delegate.AttackDelegate;
import de.rub.nds.tlsbreaker.attacks.pkcs1.BleichenbacherWorkflowType;

import java.util.LinkedList;
import java.util.List;

/**
 *
 */
public class BleichenbacherCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "bleichenbacher";

    @ParametersDelegate
    private ClientDelegate clientDelegate;

    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;

    @ParametersDelegate
    private AttackDelegate attackDelegate;

    @Parameter(names = "-encrypted_premaster_secret",
        description = "Encrypted premaster secret from the RSA client "
            + "key exchange message. You can retrieve this message from the Wireshark traffic. Find the client key "
            + "exchange message, right click on the \"EncryptedPremaster\" value and copy this value as a Hex Stream.")
    private String encryptedPremasterSecret;

    @Parameter(names = "-type", description = "Type of the Bleichenbacher test. FAST contains only basic server test "
        + "queries. FULL results in a comprehensive server evaluation.")
    private Type type = Type.FAST;

    @Parameter(names = "-msgPkcsConform", description = "Used by the real Bleichenbacher attack. Indicates whether the "
        + "original message that we are going to decrypt is PKCS#1 conform or not (more precisely, whether it starts "
        + "with 0x00 0x02).", arity = 1)
    private boolean msgPkcsConform = true;

    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    @Parameter(names = "-workflowType", description = "Which workflow traces should be tested with")
    private BleichenbacherWorkflowType workflowType = BleichenbacherWorkflowType.CKE_CCS_FIN;

    /**
     * How many rescans should be done
     */
    private int numberOfIterations = 3;

    /**
     *
     * @param delegate
     */
    public BleichenbacherCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        ciphersuiteDelegate = new CipherSuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        attackDelegate = new AttackDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(attackDelegate);
        addDelegate(starttlsDelegate);
    }

    /**
     *
     * @return
     */
    public Type getType() {
        return type;
    }

    /**
     *
     * @param type
     */
    public void setType(Type type) {
        this.type = type;
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuites = new LinkedList<>();
            for (CipherSuite suite : CipherSuite.getImplemented()) {
                if (AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.RSA
                    || AlgorithmResolver.getKeyExchangeAlgorithm(suite) == KeyExchangeAlgorithm.PSK_RSA) {
                    cipherSuites.add(suite);
                }
            }
            config.setDefaultClientSupportedCipherSuites(cipherSuites);
        }
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterIOException(true);
        config.setStopActionsAfterFatal(false);
        config.setStopReceivingAfterFatal(false);
        config.setAddRenegotiationInfoExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddECPointFormatExtension(false);
        config.setAddEllipticCurveExtension(false);
        config.setWorkflowExecutorShouldClose(false);

        return config;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    /**
     *
     * @return
     */
    public String getEncryptedPremasterSecret() {
        return encryptedPremasterSecret;
    }

    /**
     *
     * @return
     */
    public boolean isMsgPkcsConform() {
        return msgPkcsConform;
    }

    /**
     *
     */
    public enum Type {

        /**
         *
         */
        FULL,
        /**
         *
         */
        FAST
    }

    public BleichenbacherWorkflowType getWorkflowType() {
        return workflowType;
    }

    public void setWorkflowType(BleichenbacherWorkflowType workflowType) {
        this.workflowType = workflowType;
    }

    public int getNumberOfIterations() {
        return numberOfIterations;
    }

    public void setNumberOfIterations(int mapListDepth) {
        this.numberOfIterations = mapListDepth;
    }

    public CipherSuiteDelegate getCipherSuiteDelegate() {
        return ciphersuiteDelegate;
    }

    public ProtocolVersionDelegate getProtocolVersionDelegate() {
        return protocolVersionDelegate;
    }
}
