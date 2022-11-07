package de.rub.nds.tlsbreaker.breakercommons.psk.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.CipherSuiteDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.ProtocolVersionDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsbreaker.breakercommons.config.AttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.PcapAttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.AttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.exception.WordlistNotFoundException;
import de.rub.nds.tlsbreaker.breakercommons.psk.guessprovider.GuessProviderType;

public abstract class PskBruteForcerAttackCommonCommandConfig extends AttackConfig implements PcapAttackConfig {

    @ParametersDelegate
    private CipherSuiteDelegate ciphersuiteDelegate;
    @ParametersDelegate
    private ProtocolVersionDelegate protocolVersionDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;

    @Parameter(names = { "-guessProviderType",
            "-guess_provider_type" }, description = "Chooses how the BruteForcer will choose the keys to guess")
    private GuessProviderType guessProviderType = GuessProviderType.INCREMENTING;

    @Parameter(names = { "-guessProviderInputFile",
            "-guess_provider_input_file" }, description = "Set the path to an input file which can be used in the guess provider eg. a path to a wordlist")
    private String guessProviderInputFile = null;

    @Parameter(names = "-pcap", description = "Location of the pcap file that will be used for the Invalid Curve Attack.")
    private String pcapFileLocation;

    protected PskBruteForcerAttackCommonCommandConfig(GeneralDelegate generalDelegate) {
        super(generalDelegate);
        ciphersuiteDelegate = new CipherSuiteDelegate();
        protocolVersionDelegate = new ProtocolVersionDelegate();
        attackDelegate = new AttackDelegate();
        addDelegate(ciphersuiteDelegate);
        addDelegate(protocolVersionDelegate);
        addDelegate(attackDelegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        if (ciphersuiteDelegate.getCipherSuites() == null) {
            List<CipherSuite> cipherSuiteList = new LinkedList<>();
            for (CipherSuite cipherSuite : CipherSuite.getImplemented()) {
                if (cipherSuite.isPsk()) {
                    cipherSuiteList.add(cipherSuite);
                }
            }
            config.setDefaultClientSupportedCipherSuites(cipherSuiteList);
        }
        config.setQuickReceive(true);
        config.setEarlyStop(true);
        config.setStopActionsAfterFatal(true);
        return config;
    }

    public InputStream getGuessProviderInputStream() {
        if (guessProviderInputFile == null) {
            if (guessProviderType == GuessProviderType.WORDLIST) {
                return (PskBruteForcerAttackCommonCommandConfig.class.getClassLoader()
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

    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    public GuessProviderType getGuessProviderType() {
        return guessProviderType;
    }

    public void setGuessProviderType(GuessProviderType guessProviderType) {
        this.guessProviderType = guessProviderType;
    }

    public String getPcapFileLocation() {
        return pcapFileLocation;
    }

    public String getGuessProviderInputFile() {
        return guessProviderInputFile;
    }

    public void setGuessProviderInputFile(String guessProviderInputFile) {
        this.guessProviderInputFile = guessProviderInputFile;
    }
}
