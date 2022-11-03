/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed;

import java.io.IOException;

import com.beust.jcommander.JCommander;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.heartbleed.config.HeartbleedCommandConfig;
import de.rub.nds.tlsbreaker.heartbleed.impl.HeartbleedAttacker;
import de.rub.nds.tlsbreaker.heartbleed.impl.HeartbleedPcapFileHandler;

public class Main {
    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        HeartbleedCommandConfig attackConfig = new HeartbleedCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(attackConfig).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }
        PcapFileHandler pcapFileHandler = new HeartbleedPcapFileHandler(attackConfig);
        if (!CommonMain.optionallyHandlePcap(attackConfig, pcapFileHandler)) {
            Attacker<?> attacker = new HeartbleedAttacker(attackConfig,
                    attackConfig.createConfig());
            attacker.run();
        }
    }
}
