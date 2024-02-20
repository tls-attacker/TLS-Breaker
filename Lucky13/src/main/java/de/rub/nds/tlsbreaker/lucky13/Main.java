/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.lucky13;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.lucky13.config.Lucky13CommandConfig;
import de.rub.nds.tlsbreaker.lucky13.impl.Lucky13Attacker;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        Lucky13CommandConfig attackConfig = new Lucky13CommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(attackConfig).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        Attacker<?> attacker = new Lucky13Attacker(attackConfig, attackConfig.createConfig());
        attacker.run();
    }
}
