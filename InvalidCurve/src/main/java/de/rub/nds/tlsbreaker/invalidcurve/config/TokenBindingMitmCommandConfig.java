/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.MitmDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.TimeoutDelegate;

/**
 *
 */
public class TokenBindingMitmCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "token_binding_mitm";

    @Parameter(names = "-chrome", description = "Set this if using chrome. Allows to handle multiple requests.")
    private Boolean chrome = false;

    @ParametersDelegate
    private MitmDelegate mitmDelegate;
    @ParametersDelegate
    private TimeoutDelegate timeoutDelegate;

    /**
     *
     * @param delegate
     */
    public TokenBindingMitmCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        mitmDelegate = new MitmDelegate();
        addDelegate(mitmDelegate);
        timeoutDelegate = new TimeoutDelegate();
        addDelegate(timeoutDelegate);
    }

    /**
     *
     * @return
     */
    public Boolean isChrome() {
        return chrome;
    }

    /**
     *
     * @param chrome
     */
    public void setChrome(Boolean chrome) {
        this.chrome = chrome;
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
}
