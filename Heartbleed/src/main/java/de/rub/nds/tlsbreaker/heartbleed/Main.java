/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.impl.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.util.file.FileUtils;
import de.rub.nds.tlsbreaker.heartbleed.config.HeartbleedCommandConfig;
import de.rub.nds.tlsbreaker.heartbleed.impl.HeartbleedAttacker;
import de.rub.nds.tlsbreaker.heartbleed.impl.HeartbleedPcapFileHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Objects;

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
        HeartbleedCommandConfig heartbleed = new HeartbleedCommandConfig(generalDelegate);

        JCommander jc = JCommander.newBuilder().addObject(heartbleed).build();
        try {
            jc.parse(args);
        } catch (ParameterException ex) {
            ex.usage();
            return;
        }

        if (generalDelegate.isHelp()) {
            jc.usage();
            return;
        }

        if (heartbleed.getPcapFileLocation() != null) {
            if (FileUtils.isFileExists(heartbleed.getPcapFileLocation())) {
                try {
                    CONSOLE.info("Pcap file location = " + heartbleed.getPcapFileLocation());
                    HeartbleedPcapFileHandler pcapFileHandler = new HeartbleedPcapFileHandler(heartbleed);
                    pcapFileHandler.handlePcapFile();
                } catch (UnsupportedOperationException e) {
                    CONSOLE.error(e.getMessage());

                }
            } else {
                CONSOLE.error("Invalid File Path!");
            }
        } else {
            checkVulnerabilityOrExecuteAttack(heartbleed);
        }
        System.exit(0);
    }

    private static void checkVulnerabilityOrExecuteAttack(HeartbleedCommandConfig heartbleed) {
        Attacker<? extends TLSDelegateConfig> attacker = new HeartbleedAttacker(heartbleed, heartbleed.createConfig());

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
