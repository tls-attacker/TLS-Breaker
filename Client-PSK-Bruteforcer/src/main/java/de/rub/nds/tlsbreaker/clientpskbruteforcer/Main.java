/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer;

import java.io.IOException;

import com.beust.jcommander.JCommander;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.clientpskbruteforcer.config.PskBruteForcerAttackClientCommandConfig;
import de.rub.nds.tlsbreaker.clientpskbruteforcer.impl.PskBruteForcerAttackClient;
import de.rub.nds.tlsbreaker.clientpskbruteforcer.impl.PskBruteForcerClientPcapFileHandler;

/**
 *
 */
public class Main {
    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        PskBruteForcerAttackClientCommandConfig attackConfig =
            new PskBruteForcerAttackClientCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(attackConfig).build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        attackConfig.setSkipConnectionCheck(true);

        PcapFileHandler pcapFileHandler = new PskBruteForcerClientPcapFileHandler(attackConfig);
        if (!CommonMain.optionallyHandlePcap(attackConfig, pcapFileHandler)) {
            Attacker<?> attacker = new PskBruteForcerAttackClient(attackConfig, attackConfig.createConfig());
            attacker.run();
        }
    }
}
