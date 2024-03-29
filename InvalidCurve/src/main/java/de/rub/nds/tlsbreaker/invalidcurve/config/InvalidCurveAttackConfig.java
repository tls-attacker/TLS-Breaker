/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.invalidcurve.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.converters.BigIntegerConverter;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsbreaker.breakercommons.config.AttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.PcapAttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.AttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ClientDelegate;
import de.rub.nds.tlsbreaker.invalidcurve.ec.ICEAttacker;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

/** */
public class InvalidCurveAttackConfig extends AttackConfig implements PcapAttackConfig {

    /** */
    public static final String ATTACK_COMMAND = "invalid_curve";

    @Parameter(names = "-named_curve", description = "Named curve to be used")
    private NamedGroup namedGroup = NamedGroup.SECP256R1;

    @Parameter(
            names = "-additional_equations",
            description =
                    "Additional equations used when attacking Oracle JSSE server (needed because of a faulty JSSE implementation).")
    private int additionalEquations = 3;

    @Parameter(
            names = "-server_type",
            description =
                    "Allows to switch between a normal vulnerable server type and an Oracle server type (for oracle a slightly different algorithm is needed).")
    private ICEAttacker.ServerType serverType = ICEAttacker.ServerType.NORMAL;

    /** EC field size, currently set to 32, works for curves with 256 bits! */
    @Parameter(names = "-curve_field_size", description = "Curve field size. 32 works for 256bits.")
    private int curveFieldSize = 32;

    @Parameter(names = "-protocol_flows", description = "Number of Protocol flows")
    private int protocolFlows = 15;

    @Parameter(names = "-key_offset", description = "Offset of the first attempted secretkey")
    private int keyOffset = 0;

    // These are for scanning only
    @Parameter(
            names = "-premaster_secret",
            description = "Premaster Secret String (use 0x at the beginning for a hex value)",
            hidden = true,
            converter = BigIntegerConverter.class)
    private BigInteger premasterSecret;

    @Parameter(
            names = "-public_point_base_x",
            hidden = true,
            description =
                    "Public key point coordinate X sent to the server (use 0x at the beginning for a hex value)",
            converter = BigIntegerConverter.class)
    private BigInteger publicPointBaseX =
            new BigInteger("b70bf043c144935756f8f4578c369cf960ee510a5a0f90e93a373a21f0d1397f", 16);

    @Parameter(
            names = "-public_point_base_y",
            hidden = true,
            description =
                    "Public key point coordinate Y sent to the server (use 0x at the beginning for a hex value)",
            converter = BigIntegerConverter.class)
    private BigInteger publicPointBaseY =
            new BigInteger("4a2e0ded57a5156bb82eb4314c37fd4155395a7e51988af289cce531b9c17192", 16);

    @Parameter(
            names = "-ephemeral",
            description =
                    "If set to true, the attack with ephemeral cipher suites (ECDHE) is attempted.")
    private boolean ephemeral = false;

    @ParametersDelegate private ClientDelegate clientDelegate;

    @ParametersDelegate private CipherSuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate private ProtocolVersionDelegate protocolVersionDelegate;

    @ParametersDelegate private AttackDelegate attackDelegate;

    @ParametersDelegate private StarttlsDelegate starttlsDelegate;

    /** The twisted curve to simulate server's x-only ladder */
    private EllipticCurveOverFp twistedCurve;

    private boolean curveTwistAttack = false;

    @Parameter(
            names = "-curve_twist_d",
            hidden = true,
            description = "Non quadratic residue used to obtain twisted curve",
            converter = BigIntegerConverter.class)
    private BigInteger curveTwistD;

    /** Ignore server's preferences and use the specified PointFormat instead */
    @Parameter(names = "-point_format", description = "The format used for the public key")
    private ECPointFormat pointCompressionFormat = ECPointFormat.UNCOMPRESSED;

    @Parameter(
            names = "-renegotiation",
            description =
                    "If set to true, the attack will be carried out in a renegotiation handshake")
    private boolean attackInRenegotiation = false;

    @Parameter(
            names = "-pcap",
            description =
                    "Location of the pcap file that will be used for the Invalid Curve Attack.")
    private String pcapFileLocation;

    /**
     * @param delegate
     */
    public InvalidCurveAttackConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        this.getNamedGroup();
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
     * @return
     */
    public BigInteger getPremasterSecret() {
        return premasterSecret;
    }

    /**
     * @param premasterSecret
     */
    public void setPremasterSecret(BigInteger premasterSecret) {
        this.premasterSecret = premasterSecret;
    }

    /**
     * @return
     */
    public BigInteger getPublicPointBaseX() {
        return publicPointBaseX;
    }

    /**
     * @param publicPointBaseX
     */
    public void setPublicPointBaseX(BigInteger publicPointBaseX) {
        this.publicPointBaseX = publicPointBaseX;
    }

    /**
     * @return
     */
    public BigInteger getPublicPointBaseY() {
        return publicPointBaseY;
    }

    /**
     * @param publicPointBaseY
     */
    public void setPublicPointBaseY(BigInteger publicPointBaseY) {
        this.publicPointBaseY = publicPointBaseY;
    }

    /**
     * @return
     */
    public NamedGroup getNamedGroup() {
        return namedGroup;
    }

    /**
     * @param namedGroup
     */
    public void setNamedGroup(NamedGroup namedGroup) {
        this.namedGroup = namedGroup;
    }

    /**
     * @return
     */
    public int getCurveFieldSize() {
        return curveFieldSize;
    }

    /**
     * @param curveFieldSize
     */
    public void setCurveFieldSize(int curveFieldSize) {
        this.curveFieldSize = curveFieldSize;
    }

    /**
     * @return
     */
    public int getProtocolFlows() {
        return protocolFlows;
    }

    /**
     * @param protocolFlows
     */
    public void setProtocolFlows(int protocolFlows) {
        this.protocolFlows = protocolFlows;
    }

    /**
     * @return
     */
    public int getAdditionalEquations() {
        return additionalEquations;
    }

    /**
     * @param additionalEquations
     */
    public void setAdditionalEquations(int additionalEquations) {
        this.additionalEquations = additionalEquations;
    }

    /**
     * @return
     */
    public ICEAttacker.ServerType getServerType() {
        return serverType;
    }

    /**
     * @param serverType
     */
    public void setServerType(ICEAttacker.ServerType serverType) {
        this.serverType = serverType;
    }

    /**
     * @return
     */
    public boolean isEphemeral() {
        return ephemeral;
    }

    /**
     * @param ephemeral
     */
    public void setEphemeral(boolean ephemeral) {
        this.ephemeral = ephemeral;
    }

    /**
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    /**
     * @return the curveTwistAttack
     */
    public boolean isCurveTwistAttack() {
        return curveTwistAttack;
    }

    /**
     * @param curveTwistAttack the curveTwistAttack to set
     */
    public void setCurveTwistAttack(boolean curveTwistAttack) {
        this.curveTwistAttack = curveTwistAttack;
    }

    /**
     * @return the twistedCurve
     */
    public EllipticCurveOverFp getTwistedCurve() {
        return twistedCurve;
    }

    /**
     * @param twistedCurve the twistedCurve to set
     */
    public void setTwistedCurve(EllipticCurveOverFp twistedCurve) {
        this.twistedCurve = twistedCurve;
    }

    /**
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        List<CipherSuite> cipherSuites = new LinkedList<>();
        if (ephemeral) {
            cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA);
            config.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        } else {
            cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
            cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
            cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
            cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
            config.setDefaultSelectedCipherSuite(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        }
        config.setQuickReceive(true);
        config.setStopActionsAfterFatal(true);
        config.setStopReceivingAfterFatal(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterIOException(true);
        config.setStopTraceAfterUnexpected(true);
        config.setAddECPointFormatExtension(true);
        config.setAddEllipticCurveExtension(true);
        config.setAddServerNameIndicationExtension(true);
        config.setAddRenegotiationInfoExtension(true);
        config.setDefaultClientSupportedCipherSuites(cipherSuites);
        List<NamedGroup> namedCurves = new LinkedList<>();
        namedCurves.add(namedGroup);
        config.setDefaultClientNamedGroups(namedCurves);
        config.setWorkflowTraceType(WorkflowTraceType.HANDSHAKE);
        return config;
    }

    /**
     * @return the curveTwistD
     */
    public BigInteger getCurveTwistD() {
        return curveTwistD;
    }

    /**
     * @param curveTwistD the curveTwistD to set
     */
    public void setCurveTwistD(BigInteger curveTwistD) {
        this.curveTwistD = curveTwistD;
    }

    /**
     * @return the pointCompressionFormat
     */
    public ECPointFormat getPointCompressionFormat() {
        return pointCompressionFormat;
    }

    /**
     * @param pointCompressionFormat the pointCompressionFormat to set
     */
    public void setPointCompressionFormat(ECPointFormat pointCompressionFormat) {
        this.pointCompressionFormat = pointCompressionFormat;
    }

    /**
     * @return the attackInRenegotiation
     */
    public boolean isAttackInRenegotiation() {
        return attackInRenegotiation;
    }

    /**
     * @param attackInRenegotiation the attackInRenegotiation to set
     */
    public void setAttackInRenegotiation(boolean attackInRenegotiation) {
        this.attackInRenegotiation = attackInRenegotiation;
    }

    public int getKeyOffset() {
        return keyOffset;
    }

    public void setKeyOffset(int keyOffset) {
        this.keyOffset = keyOffset;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public String getPcapFileLocation() {
        return pcapFileLocation;
    }
}
