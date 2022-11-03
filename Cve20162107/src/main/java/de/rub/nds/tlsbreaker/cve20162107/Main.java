/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.cve20162107;

import java.io.IOException;

import com.beust.jcommander.JCommander;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.cve20162107.config.Cve20162107CommandConfig;
import de.rub.nds.tlsbreaker.cve20162107.impl.Cve20162107Attacker;

public class Main {

    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        Cve20162107CommandConfig cve20162107 = new Cve20162107CommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(cve20162107).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        Attacker<? extends TLSDelegateConfig> attacker =
            new Cve20162107Attacker(cve20162107, cve20162107.createConfig());
        attacker.run();
    }
}
