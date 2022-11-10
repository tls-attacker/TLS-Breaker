/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.poodle;

import java.io.IOException;

import com.beust.jcommander.JCommander;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.poodle.config.PoodleCommandConfig;
import de.rub.nds.tlsbreaker.poodle.impl.PoodleAttacker;

public class Main {

    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        PoodleCommandConfig poodle = new PoodleCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(poodle).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        Attacker<?> attacker = new PoodleAttacker(poodle, poodle.createConfig());
        attacker.run();
    }
}
