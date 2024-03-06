/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.breakercommons;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.attacker.PcapFileHandler;
import de.rub.nds.tlsbreaker.breakercommons.config.PcapAttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;

public class CommonMain {

    private CommonMain() {}

    public static boolean parseConfig(
            String[] args, JCommander jc, GeneralDelegate generalDelegate) {
        try {
            jc.parse(args);
        } catch (ParameterException ex) {
            String parsedCommand = ex.getJCommander().getParsedCommand();
            if (parsedCommand != null) {
                ex.getJCommander().getUsageFormatter().usage(parsedCommand);
            } else {
                ex.usage();
            }
            return false;
        }

        if (!jc.getCommands().isEmpty()) {
            // jc has commands configured
            if (jc.getParsedCommand() == null) {
                // no command was specified
                jc.usage();
                return false;
            }
            if (generalDelegate.isHelp()) {
                // command was specified but with help
                jc.getUsageFormatter().usage(jc.getParsedCommand());
                return false;
            }
        } else if (generalDelegate.isHelp()) {
            // help was specified (and there are no commands)
            jc.usage();
            return false;
        }
        // could parse
        return true;
    }

    public static boolean optionallyHandlePcap(
            PcapAttackConfig attackConfig, PcapFileHandler pcapFileHandler) {
        final String pcapLocation = attackConfig.getPcapFileLocation();
        if (pcapLocation == null) {
            return false;
        }
        if (FileUtils.isFileExists(pcapLocation)) {
            try {
                CONSOLE.info("Pcap file location: {}", pcapLocation);
                pcapFileHandler.handlePcapFile();
            } catch (UnsupportedOperationException e) {
                CONSOLE.error("Invalid option selected! Please run the jar file again.");
            }
        } else {
            CONSOLE.error("Invalid File Path!");
        }
        return true;
    }
}
