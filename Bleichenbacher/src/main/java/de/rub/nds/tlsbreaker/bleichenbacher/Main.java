/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on
							TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit
							GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.bleichenbacher;

/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.JCommander.Builder;
import com.beust.jcommander.ParameterException;
import de.rub.nds.tlsattacker.core.config.TLSDelegateConfig;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsbreaker.bleichenbacher.config.BleichenbacherCommandConfig;
import de.rub.nds.tlsbreaker.bleichenbacher.config.delegate.GeneralAttackDelegate;
import de.rub.nds.tlsbreaker.bleichenbacher.impl.Attacker;
import de.rub.nds.tlsbreaker.bleichenbacher.impl.BleichenbacherAttacker;

import java.util.Objects;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

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

        BleichenbacherCommandConfig bleichenbacherTest = new BleichenbacherCommandConfig(generalDelegate);
        builder.addCommand(BleichenbacherCommandConfig.ATTACK_COMMAND, bleichenbacherTest);

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

        Attacker<? extends TLSDelegateConfig> attacker = null;

        switch (jc.getParsedCommand()) {
            case BleichenbacherCommandConfig.ATTACK_COMMAND:
                attacker = new BleichenbacherAttacker(bleichenbacherTest, bleichenbacherTest.createConfig());
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
