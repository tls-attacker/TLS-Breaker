/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.drownattack.impl.drown;

import static de.rub.nds.tlsattacker.util.ConsoleLogger.CONSOLE;

import de.rub.nds.modifiablevariable.util.ArrayConverter;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsbreaker.breakercommons.attacker.Attacker;
import de.rub.nds.tlsbreaker.breakercommons.attacker.VulnerabilityType;
import de.rub.nds.tlsbreaker.breakercommons.constants.DrownVulnerabilityType;
import de.rub.nds.tlsbreaker.drownattack.config.BaseDrownCommandConfig;
import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

abstract class BaseDrownAttacker extends Attacker<BaseDrownCommandConfig> {

    // Raw bytes of captured Premaster secrets to be decrypted
    protected List<byte[]> premasterSecrets;

    public BaseDrownAttacker(BaseDrownCommandConfig config, Config baseConfig) {
        super(config, baseConfig);

        if (config.isExecuteAttack()) {
            String secretsPath = config.getPremasterSecretsFilePath();
            if (secretsPath == null) {
                throw new ConfigurationException(
                        "Premaster secrets file is required for the attack");
            }

            FileReader secretsReaderUnbuffered;
            try {
                secretsReaderUnbuffered = new FileReader(secretsPath);
            } catch (FileNotFoundException e) {
                throw new ConfigurationException("Premaster secrets file not found");
            }
            BufferedReader secretsReaderBuffered = new BufferedReader(secretsReaderUnbuffered);

            premasterSecrets = new ArrayList<byte[]>();
            String line;

            try {
                while ((line = secretsReaderBuffered.readLine()) != null) {
                    byte[] secret = ArrayConverter.hexStringToByteArray(line);
                    premasterSecrets.add(secret);
                }
                secretsReaderBuffered.close();
                secretsReaderUnbuffered.close();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Override
    public VulnerabilityType isVulnerable() {
        DrownVulnerabilityType type = getDrownVulnerabilityType();
        switch (type) {
            case GENERAL:
                CONSOLE.error("Server is vulnerable to the full General DROWN attack");
                return VulnerabilityType.TRUE;
            case SPECIAL:
                CONSOLE.error("Server is vulnerable to the full Special DROWN attack");
                return VulnerabilityType.TRUE;
            case SSL2:
                CONSOLE.warn(
                        "Server supports SSL2, but not any weak cipher suites, so is not vulnerable to DROWN");
                return VulnerabilityType.FALSE;
            case NONE:
                return VulnerabilityType.FALSE;
            case UNKNOWN:
                CONSOLE.info(
                        "Could not execute Workflow, check previous messages or increase log level");
                return VulnerabilityType.NULL;
            default:
                return VulnerabilityType.NULL;
        }
    }

    public abstract DrownVulnerabilityType getDrownVulnerabilityType();
}
