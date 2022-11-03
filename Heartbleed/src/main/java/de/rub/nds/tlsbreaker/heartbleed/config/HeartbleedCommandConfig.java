/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.config;

import java.util.LinkedList;
import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.AlgorithmResolver;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.ECPointFormat;
import de.rub.nds.tlsattacker.core.constants.HeartbeatMode;
import de.rub.nds.tlsattacker.core.constants.KeyExchangeAlgorithm;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsbreaker.breakercommons.config.AttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.PcapAttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.AttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ClientDelegate;

/**
 *
 */
public class HeartbleedCommandConfig extends AttackConfig implements PcapAttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "heartbleed";

    @Parameter(names = "-payload_length", description = "Payload length sent in the client heartbeat message")
    private Integer payloadLength = 65535;

    @ParametersDelegate
    private ClientDelegate clientDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;
    @Parameter(names = "-pcap", description = "Location of the pcap file that will be used for the Attack.")
    private String pcapFileLocation;
    @Parameter(names = "-heartbeats", description = "Number of heartbeat messages to be sent.")
    private Integer heartbeatCount = 5;
    @Parameter(names = "-dump", description = "Dumps the raw server data to the specified file.")
    private String outputDumpFileLocation;
    @Parameter(names = "-process_dump",
        description = "Location of the text file (memory dump) that will be used " + "to search for the private key.")
    private String inputDumpFileLocation;

    /**
     *
     * @param delegate
     */
    public HeartbleedCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        attackDelegate = new AttackDelegate();
        ciphersuiteDelegate = new CipherSuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
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
    public Integer getPayloadLength() {
        return payloadLength;
    }

    /**
     *
     * @param payloadLength
     */
    public void setPayloadLength(Integer payloadLength) {
        this.payloadLength = payloadLength;
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
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setDefaultClientSupportedCipherSuites(getCipherSuites());
        config.setDefaultClientNamedGroups(getNamedGroups());
        config.setDefaultClientSupportedPointFormats(getPointFormats());
        config.setDefaultClientSupportedSignatureAndHashAlgorithms(getSignatureAndHashAlgorithm());
        config.setDefaultPaddingExtensionBytes(new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
        config.setAddEllipticCurveExtension(true);
        config.setAddSessionTicketTLSExtension(true);
        config.setAddHeartbeatExtension(true);
        config.setHeartbeatMode(HeartbeatMode.PEER_ALLOWED_TO_SEND);
        config.setAddRenegotiationInfoExtension(false);
        // config.setAddServerNameIndicationExtension(true);
        config.setAddSignatureAndHashAlgorithmsExtension(true);
        config.setAddPaddingExtension(true);
        config.setQuickReceive(true);
        config.setStopActionsAfterFatal(true);
        config.setStopActionsAfterIOException(true);
        config.setStopReceivingAfterFatal(true);
        config.setEarlyStop(true);
        boolean containsEc = false;
        for (CipherSuite suite : config.getDefaultClientSupportedCipherSuites()) {
            KeyExchangeAlgorithm keyExchangeAlgorithm = AlgorithmResolver.getKeyExchangeAlgorithm(suite);
            if (keyExchangeAlgorithm != null && keyExchangeAlgorithm.name().toUpperCase().contains("EC")) {
                containsEc = true;
                break;
            }
        }
        config.setAddECPointFormatExtension(containsEc);
        config.setAddEllipticCurveExtension(containsEc);
        return config;
    }

    private List<SignatureAndHashAlgorithm> getSignatureAndHashAlgorithm() {
        List<SignatureAndHashAlgorithm> signatureAndHashAlgorithms = new LinkedList<>();
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA512);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA512);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA512);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA384);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA384);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA384);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA256);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA256);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA256);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA224);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA224);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA224);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.RSA_SHA1);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.DSA_SHA1);
        signatureAndHashAlgorithms.add(SignatureAndHashAlgorithm.ECDSA_SHA1);
        return signatureAndHashAlgorithms;
    }

    private List<ECPointFormat> getPointFormats() {
        List<ECPointFormat> pointFormats = new LinkedList<>();
        pointFormats.add(ECPointFormat.UNCOMPRESSED);
        pointFormats.add(ECPointFormat.ANSIX962_COMPRESSED_PRIME);
        pointFormats.add(ECPointFormat.ANSIX962_COMPRESSED_CHAR2);
        return pointFormats;
    }

    private List<NamedGroup> getNamedGroups() {
        List<NamedGroup> namedCurves = new LinkedList<>();
        namedCurves.add(NamedGroup.SECT571R1);
        namedCurves.add(NamedGroup.SECT571K1);
        namedCurves.add(NamedGroup.SECP521R1);
        namedCurves.add(NamedGroup.SECT409K1);
        namedCurves.add(NamedGroup.SECT409R1);
        namedCurves.add(NamedGroup.SECP384R1);
        namedCurves.add(NamedGroup.SECT283K1);
        namedCurves.add(NamedGroup.SECT283R1);
        namedCurves.add(NamedGroup.SECP256K1);
        namedCurves.add(NamedGroup.SECP256R1);
        namedCurves.add(NamedGroup.SECT239K1);
        namedCurves.add(NamedGroup.SECT233K1);
        namedCurves.add(NamedGroup.SECT233R1);
        namedCurves.add(NamedGroup.SECP224K1);
        namedCurves.add(NamedGroup.SECP224R1);
        namedCurves.add(NamedGroup.SECT193R1);
        namedCurves.add(NamedGroup.SECT193R2);
        namedCurves.add(NamedGroup.SECP192K1);
        namedCurves.add(NamedGroup.SECP192R1);
        namedCurves.add(NamedGroup.SECT163K1);
        namedCurves.add(NamedGroup.SECT163R1);
        namedCurves.add(NamedGroup.SECT163R2);
        namedCurves.add(NamedGroup.SECP160K1);
        namedCurves.add(NamedGroup.SECP160R1);
        namedCurves.add(NamedGroup.SECP160R2);
        return namedCurves;
    }

    private List<CipherSuite> getCipherSuites() {
        List<CipherSuite> cipherSuites = new LinkedList<>();
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_CAMELLIA_256_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_SEED_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_SEED_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_GCM_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA256);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_SEED_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_CAMELLIA_128_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_IDEA_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_RSA_WITH_RC4_128_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_RSA_WITH_RC4_128_SHA);
        cipherSuites.add(CipherSuite.TLS_ECDH_ECDSA_WITH_RC4_128_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_WITH_DES_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_WITH_DES_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_WITH_DES_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
        cipherSuites.add(CipherSuite.TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5);
        cipherSuites.add(CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5);
        cipherSuites.add(CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV);
        return cipherSuites;
    }

    public String getPcapFileLocation() {
        return pcapFileLocation;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public Integer getHeartbeatCount() {
        return heartbeatCount;
    }

    public String getOutputDumpFileLocation() {
        return outputDumpFileLocation;
    }

    public String getInputDumpFileLocation() {
        return inputDumpFileLocation;
    }
}
