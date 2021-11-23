/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.config;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;

public class GeneralDrownCommandConfig extends BaseDrownCommandConfig {

    public static final String COMMAND = "generalDrown";

    public GeneralDrownCommandConfig(GeneralDelegate delegate) {
        super(delegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        return config;
    }

}
