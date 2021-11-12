/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.attacks.config;

import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import java.io.InputStream;
import org.junit.Test;

/**
 *
 *
 */
public class SimpleMitmProxyCommandConfigTest {

    private SimpleMitmProxyCommandConfig cmdConfig;
    private InputStream inputKeyStream;

    /**
     *
     */
    public SimpleMitmProxyCommandConfigTest() {
        cmdConfig = new SimpleMitmProxyCommandConfig(new GeneralDelegate());
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyRsaWithPassword() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyEc() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyEcWithPassword() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyDh() {
    }

    /**
     *
     */
    @Test
    public void testLoadPrivateKeyDhWithPassword() {
    }

}
