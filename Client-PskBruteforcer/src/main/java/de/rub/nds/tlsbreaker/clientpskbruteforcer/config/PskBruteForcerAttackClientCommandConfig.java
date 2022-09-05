/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer.config;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;

import de.rub.nds.tlsbreaker.breakercommons.config.AttackConfig;
import de.rub.nds.tlsbreaker.clientpskbruteforcer.bruteforce.GuessProviderType;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.AttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.exception.WordlistNotFoundException;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
//import de.rub.nds.tlsattacker.core.config.delegate.ServerDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ClientDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ServerDelegate;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

//#####
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ClientDelegate;

//#######
/**
 *
 */
public class PskBruteForcerAttackClientCommandConfig extends AttackConfig {

    /**
     *
     */
    public static final String ATTACK_COMMAND = "pskbruteforcerclient";

    @ParametersDelegate
    private ServerDelegate serverDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;
    @Parameter(names = { "-guessProviderType", "-guess_provider_type" },
        description = "Chooses how the BruteForcer will choose the keys to guess")
    private GuessProviderType guessProviderType = GuessProviderType.INCREMENTING;
    @Parameter(names = { "-guessProviderInputFile", "-guess_provider_input_file" },
        description = "Set the path to an input file which can be used in the guess provider eg. a path to a wordlist")
    private String guessProviderInputFile = null;

    @Parameter(names = "-pcap",
        description = "Location of the pcap file that will be used for the Invalid Curve Attack.")
    private String pcapFileLocation;

    /**
     *
     * @param delegate
     */
    public PskBruteForcerAttackClientCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        serverDelegate = new ServerDelegate();
        attackDelegate = new AttackDelegate();
        ciphersuiteDelegate = new CipherSuiteDelegate();
        addDelegate(serverDelegate);
        addDelegate(attackDelegate);
        addDelegate(ciphersuiteDelegate);
    }

    /**
     *
     * @return
     */
    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setQuickReceive(true);
        config.setEarlyStop(true);

        return config;
    }

    /**
     *
     * @return
     */
    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    /**
     *
     * @return
     */
    public String getGuessProviderInputFile() {
        return guessProviderInputFile;
    }

    /**
     *
     * @return
     */
    public InputStream getGuessProviderInputStream() {
        if (this.guessProviderInputFile == null) {
            if (guessProviderType == GuessProviderType.WORDLIST) {
                return (PskBruteForcerAttackClientCommandConfig.class.getClassLoader()
                    .getResourceAsStream("psk_common_passwords.txt"));
            } else {
                return System.in;
            }
        } else {
            File file = new File(getGuessProviderInputFile());
            try {
                return new FileInputStream(file);
            } catch (FileNotFoundException ex) {
                throw new WordlistNotFoundException("Wordlist not found: " + file.getAbsolutePath(), ex);
            }
        }
    }

    /**
     *
     * @return
     */
    public GuessProviderType getGuessProviderType() {
        return guessProviderType;
    }

    public String getPcapFileLocation() {
        return pcapFileLocation;
    }

    public ServerDelegate getServerDelegate() {
        return serverDelegate;
    }

    @Override

    public void setSkipConnectionCheck(boolean skipConnectionCheck) {
        super.setSkipConnectionCheck(skipConnectionCheck);
    }

    /**
     *
     * @param guessProviderType
     */
    public void setGuessProviderType(GuessProviderType guessProviderType) {
        this.guessProviderType = guessProviderType;
    }

    public void setGuessProviderInputFile(String guessProviderInputFile) {
        this.guessProviderInputFile = guessProviderInputFile;
    }

}
