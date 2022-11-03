/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.drownattack.config;

import java.util.List;

import com.beust.jcommander.Parameter;
import com.beust.jcommander.ParametersDelegate;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.StarttlsDelegate;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.record.layer.RecordLayerType;
import de.rub.nds.tlsbreaker.breakercommons.config.AttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.PcapAttackConfig;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.AttackDelegate;
import de.rub.nds.tlsbreaker.breakercommons.config.delegate.ClientDelegate;

public abstract class BaseDrownCommandConfig extends AttackConfig implements PcapAttackConfig {

    @ParametersDelegate
    ClientDelegate clientDelegate;
    @ParametersDelegate
    private AttackDelegate attackDelegate;
    @ParametersDelegate
    private StarttlsDelegate starttlsDelegate;

    @Parameter(names = { "-premasterSecretsFile", "-premaster_secrets_file" },
        description = "File containing captured " + "Premaster secrets to be decrypted in hex format, one per line")
    private String premasterSecretsFilePath;

    @Parameter(names = "-pcap", description = "Location of the pcap file that will be used for the Attack."
        + "The server to be attacked and the associated pre-master secrets will be extracted from the given pcap file.")
    private String pcapFileLocation;

    private List<byte[]> premasterSecretsFromPcap;

    public BaseDrownCommandConfig(GeneralDelegate delegate) {
        super(delegate);
        clientDelegate = new ClientDelegate();
        attackDelegate = new AttackDelegate();
        starttlsDelegate = new StarttlsDelegate();
        addDelegate(clientDelegate);
        addDelegate(attackDelegate);
        addDelegate(starttlsDelegate);
    }

    @Override
    public Config createConfig() {
        Config config = super.createConfig();
        config.setRecordLayerType(RecordLayerType.BLOB);
        config.setHighestProtocolVersion(ProtocolVersion.SSL2);

        return config;
    }

    @Override
    public boolean isExecuteAttack() {
        return attackDelegate.isExecuteAttack();
    }

    public String getPremasterSecretsFilePath() {
        return premasterSecretsFilePath;
    }

    public String getPcapFileLocation() {
        return pcapFileLocation;
    }

    public ClientDelegate getClientDelegate() {
        return clientDelegate;
    }

    public void setPremasterSecretsFromPcap(List<byte[]> premasterSecretsFromPcap) {
        this.premasterSecretsFromPcap = premasterSecretsFromPcap;
    }

    public List<byte[]> getPremasterSecretsFromPcap() {
        return premasterSecretsFromPcap;
    }
}
