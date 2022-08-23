package de.rub.nds.tlsbreaker.simplemitmproxy.config;

import com.beust.jcommander.Parameter;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.Delegate;

public class NoCertDelegate extends Delegate {

    @Parameter(names = "-noCert", description = "Use this flag to start the proxy without a certificate.")
    private boolean noCert = false;

    public NoCertDelegate() {
    }

    @Override
    public void applyDelegate(Config config) {
        if (noCert != true) {
        }
    }
}
