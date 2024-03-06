/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.invalidcurve;

import com.beust.jcommander.JCommander;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.invalidcurve.config.InvalidCurveAttackConfig;
import de.rub.nds.tlsbreaker.invalidcurve.impl.InvalidCurveAttacker;
import de.rub.nds.tlsbreaker.invalidcurve.impl.InvalidCurvePcapFileHandler;
import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        InvalidCurveAttackConfig attackConfig = new InvalidCurveAttackConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(attackConfig).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        PcapFileHandler pcapFileHandler = new InvalidCurvePcapFileHandler(attackConfig);
        if (!CommonMain.optionallyHandlePcap(attackConfig, pcapFileHandler)) {
            Attacker<? extends TLSDelegateConfig> attacker =
                    new InvalidCurveAttacker(attackConfig, attackConfig.createConfig());
            attacker.run();
        }
    }
}
