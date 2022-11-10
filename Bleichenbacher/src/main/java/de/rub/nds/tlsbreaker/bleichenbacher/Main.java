/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher;

import java.io.IOException;

import com.beust.jcommander.JCommander;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.bleichenbacher.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsbreaker.bleichenbacher.impl.BleichenbacherAttacker;
import de.rub.nds.tlsbreaker.bleichenbacher.impl.BleichenbacherPcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;

public class Main {
    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        BleichenbacherCommandConfig attackConfig = new BleichenbacherCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(attackConfig).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        PcapFileHandler pcapFileHandler = new BleichenbacherPcapFileHandler(attackConfig);
        if (!CommonMain.optionallyHandlePcap(attackConfig, pcapFileHandler)) {
            Attacker<?> attacker = new BleichenbacherAttacker(attackConfig,
                    attackConfig.createConfig());
            attacker.run();
        }
    }
}
