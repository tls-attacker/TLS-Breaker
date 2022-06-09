/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.drownattack;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.JCommander.Builder;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;
import de.rub.nds.tlsbreaker.drownattack.config.GeneralDrownCommandConfig;
import de.rub.nds.tlsbreaker.drownattack.config.SpecialDrownCommandConfig;
import de.rub.nds.tlsbreaker.drownattack.impl.drown.DrownPcapFileHandler;
import de.rub.nds.tlsbreaker.drownattack.impl.drown.GeneralDrownAttacker;
import de.rub.nds.tlsbreaker.drownattack.impl.drown.SpecialDrownAttacker;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Objects;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

/**
 *
 */
public class Main {

    private static final Logger LOGGER = LogManager.getLogger();

    /**
     *
     * @param args
     */
    public static void main(String[] args) {
        GeneralDelegate generalDelegate = new GeneralAttackDelegate();
        Builder builder = JCommander.newBuilder().addObject(generalDelegate);

        GeneralDrownCommandConfig generalDrownConfig = new GeneralDrownCommandConfig(generalDelegate);
        builder.addCommand(GeneralDrownCommandConfig.COMMAND, generalDrownConfig);

        SpecialDrownCommandConfig specialDrownConfig = new SpecialDrownCommandConfig(generalDelegate);
        builder.addCommand(SpecialDrownCommandConfig.COMMAND, specialDrownConfig);

        JCommander jc = builder.build();

        try {
            jc.parse(args);
        } catch (ParameterException ex) {
            String parsedCommand = ex.getJCommander().getParsedCommand();
            if (parsedCommand != null) {
                ex.getJCommander().getUsageFormatter().usage(parsedCommand);
            } else {
                ex.usage();
            }
            return;
        }

        if (jc.getParsedCommand() == null) {
            jc.usage();
            return;
        }

        if (generalDelegate.isHelp()) {
            jc.getUsageFormatter().usage(jc.getParsedCommand());
            return;
        }

        if (jc.getParsedCommand() == GeneralDrownCommandConfig.COMMAND
            && generalDrownConfig.getPcapFileLocation() != null) {
            if (FileUtils.isFileExists(generalDrownConfig.getPcapFileLocation())) {
                try {
                    CONSOLE.info("Pcap file location = " + generalDrownConfig.getPcapFileLocation());
                    DrownPcapFileHandler drownPcapFileHandler = new DrownPcapFileHandler(generalDrownConfig);
                    drownPcapFileHandler.handlePcapFile();
                } catch (UnsupportedOperationException e) {
                    CONSOLE.error("Invalid option selected! Please run the jar file again.");
                }
            } else {
                CONSOLE.error("Invalid File Path!");
            }
        } else if (jc.getParsedCommand() == SpecialDrownCommandConfig.COMMAND
            && specialDrownConfig.getPcapFileLocation() != null) {
            if (FileUtils.isFileExists(specialDrownConfig.getPcapFileLocation())) {
                try {
                    CONSOLE.info("Pcap file location = " + specialDrownConfig.getPcapFileLocation());
                    DrownPcapFileHandler drownPcapFileHandler = new DrownPcapFileHandler(specialDrownConfig);
                    drownPcapFileHandler.handlePcapFile();
                } catch (UnsupportedOperationException e) {
                    CONSOLE.error("Invalid option selected! Please run the jar file again.");
                }
            } else {
                CONSOLE.error("Invalid File Path!");
            }
        } else {
            checkVulnerabilityOrExecuteAttack(jc, generalDrownConfig, specialDrownConfig);
        }
        System.exit(0);
    }

    private static void checkVulnerabilityOrExecuteAttack(JCommander jc, GeneralDrownCommandConfig generalDrownConfig,
        SpecialDrownCommandConfig specialDrownConfig) {

        Attacker<? extends TLSDelegateConfig> attacker = null;

        switch (jc.getParsedCommand()) {
            case GeneralDrownCommandConfig.COMMAND:
                attacker = new GeneralDrownAttacker(generalDrownConfig, generalDrownConfig.createConfig());
                break;
            case SpecialDrownCommandConfig.COMMAND:
                attacker = new SpecialDrownAttacker(specialDrownConfig, specialDrownConfig.createConfig());
                break;
            default:
                break;
        }

        if (attacker == null) {
            throw new ConfigurationException("Command not found");
        }

        if (attacker.getConfig().isExecuteAttack()) {
            attacker.attack();
        } else {
            try {
                Boolean result = attacker.checkVulnerability();
                if (Objects.equals(result, Boolean.TRUE)) {
                    CONSOLE.error("Vulnerable:" + result.toString());
                } else if (Objects.equals(result, Boolean.FALSE)) {
                    CONSOLE.info("Vulnerable:" + result.toString());
                } else {
                    CONSOLE.warn("Vulnerable: Uncertain");
                }
            } catch (UnsupportedOperationException e) {
                LOGGER.info("The selected attacker is currently not implemented");
            }
        }
    }
}
