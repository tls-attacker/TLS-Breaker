/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.earlyfinished;

import java.io.IOException;

import com.beust.jcommander.JCommander;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.earlyfinished.config.EarlyFinishedCommandConfig;
import de.rub.nds.tlsbreaker.earlyfinished.impl.EarlyFinishedAttacker;

public class Main {
    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        EarlyFinishedCommandConfig earlyFin = new EarlyFinishedCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(earlyFin).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        Attacker<?> attacker = new EarlyFinishedAttacker(earlyFin, earlyFin.createConfig());
        attacker.run();
    }
}
