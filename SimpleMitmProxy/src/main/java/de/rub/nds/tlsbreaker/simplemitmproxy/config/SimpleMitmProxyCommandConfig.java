/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.simplemitmproxy.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CertificateDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.MitmDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.AttackConfig;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 */
public class SimpleMitmProxyCommandConfig extends AttackConfig {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     */
    public static final String ATTACK_COMMAND = "simple_mitm_proxy";

    @ParametersDelegate
    private MitmDelegate mitmDelegate;

    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;

    @ParametersDelegate
    private CertificateDelegate certificateDelegate;

    @Parameter(names = { "-noCert", "-no_cert" },
        description = "Use the flag to signal that SimpleMitmProxy should skip the certificate" + "generation process.")
    private boolean noCert = false;

    /**
     *
     * @param delegate
     */
    public SimpleMitmProxyCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        mitmDelegate = new MitmDelegate();
        ciphersuiteDelegate = new CipherSuiteDelegate();
        certificateDelegate = new CertificateDelegate();
        addDelegate(mitmDelegate);
        addDelegate(ciphersuiteDelegate);
        addDelegate(certificateDelegate);
    }

    /*
     * Always execute attack.
     */
    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return true;
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        return config;
    }

    public boolean isNoCert() {
        return this.noCert;
    }
}
