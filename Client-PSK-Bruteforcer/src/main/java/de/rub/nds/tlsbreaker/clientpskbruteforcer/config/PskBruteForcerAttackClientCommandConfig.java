/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer.config;

import com.beust.jcommander.ParametersDelegate;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ServerDelegate;
import de.rub.nds.tlsbreaker.breakercommons.psk.config.PskBruteForcerAttackCommonCommandConfig;

public class PskBruteForcerAttackClientCommandConfig extends PskBruteForcerAttackCommonCommandConfig {
    public static final String ATTACK_COMMAND = "pskbruteforcerclient";

    @ParametersDelegate
    private ServerDelegate serverDelegate;

    public PskBruteForcerAttackClientCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        serverDelegate = new ServerDelegate();
        addDelegate(serverDelegate);
    }

    public ServerDelegate getServerDelegate() {
        return serverDelegate;
    }

}
