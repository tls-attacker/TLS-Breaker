/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.serverpskbruteforce.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ClientDelegate;
import de.rub.nds.tlsbreaker.breakercommons.psk.config.PskBruteForcerAttackCommonCommandConfig;

public class PskBruteForcerAttackServerCommandConfig
        extends PskBruteForcerAttackCommonCommandConfig {
    public static final String ATTACK_COMMAND = "pskbruteforcerserver";

    @ParametersDelegate private ClientDelegate clientDelegate;

    @Parameter(
            names = {"-clientIdentity", "-client_identity"},
            description = "Set a Client Identity")
    private String clientIdentity;

    @Parameter(
            names = {"-pskIdentity", "-psk_identity"},
            description = "Set the Psk Identity, that should be used")
    private String pskIdentity = "Client_identity";

    public PskBruteForcerAttackServerCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        addDelegate(clientDelegate);
    }

    public String getClientIdentity() {
        return clientIdentity;
    }

    public String getPskIdentity() {
        return pskIdentity;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }
}
