/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.drownattack;

import java.io.IOException;
import java.util.Objects;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.JCommander.Builder;

import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsbreaker.breakercommons.CommonMain;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;
import de.rub.nds.tlsbreaker.drownattack.config.BaseDrownCommandConfig;
import de.rub.nds.tlsbreaker.drownattack.config.GeneralDrownCommandConfig;
import de.rub.nds.tlsbreaker.drownattack.config.SpecialDrownCommandConfig;
import de.rub.nds.tlsbreaker.drownattack.impl.drown.DrownPcapFileHandler;
import de.rub.nds.tlsbreaker.drownattack.impl.drown.GeneralDrownAttacker;
import de.rub.nds.tlsbreaker.drownattack.impl.drown.SpecialDrownAttacker;

/**
 *
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    public static void main(String[] args) throws IOException {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        Builder builder = JCommander.newBuilder().addObject(generalDelegate);

        GeneralDrownCommandConfig generalDrownConfig = new GeneralDrownCommandConfig(generalDelegate);
        builder.addCommand(GeneralDrownCommandConfig.COMMAND, generalDrownConfig);

        SpecialDrownCommandConfig specialDrownConfig = new SpecialDrownCommandConfig(generalDelegate);
        builder.addCommand(SpecialDrownCommandConfig.COMMAND, specialDrownConfig);

        JCommander jc = builder.build();
        if (!CommonMain.parseConfig(args, jc, generalDelegate)) {
            return;
        }

        Attacker<?> attacker;
        BaseDrownCommandConfig selectedConfig;
        PcapFileHandler pcapFileHandler = new DrownPcapFileHandler(generalDrownConfig);
        switch (jc.getParsedCommand()) {
            case GeneralDrownCommandConfig.COMMAND:
                selectedConfig = generalDrownConfig;
                attacker = new GeneralDrownAttacker(generalDrownConfig, generalDrownConfig.createConfig());
                break;
            case SpecialDrownCommandConfig.COMMAND:
                selectedConfig = specialDrownConfig;
                attacker = new SpecialDrownAttacker(specialDrownConfig, specialDrownConfig.createConfig());
                break;
            default:
                LOGGER.error("Unknown command: {}", jc.getParsedCommand());
                return;
        }

        if (!CommonMain.optionallyHandlePcap(selectedConfig, pcapFileHandler)) {
            attacker.run();
        }
    }
}
