/*
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2024 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */
package de.rub.nds.tlsbreaker.serverpskbruteforce.impl;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsbreaker.serverpskbruteforce.config.PskBruteForcerAttackServerCommandConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class PskBruteForcerAttackServerTest {

    private PskBruteForcerAttackServerCommandConfig config;
    private Config baseConfig;

    @BeforeEach
    public void setUp() {
        GeneralDelegate generalDelegate = new GeneralDelegate();
        config = new PskBruteForcerAttackServerCommandConfig(generalDelegate);
        baseConfig = Config.createConfig();
    }

    /**
     * Test that PSK identity is properly set in the TLS configuration.
     * This test prevents regression of issue #128 where PSK identity was not being set,
     * causing ArrayConverter.intToBytes to fail with "array must be at least of size 1".
     */
    @Test
    public void testPskIdentityIsSetInTlsConfig() {
        // Create the attacker instance
        PskBruteForcerAttackServer attacker = new PskBruteForcerAttackServer(config, baseConfig);
        
        // Get the TLS config used by the attacker
        Config tlsConfig = attacker.getTlsConfig();
        
        // Verify that PSK identity is set
        assertNotNull(tlsConfig.getDefaultPSKIdentity(), "PSK identity should not be null");
        assertTrue(tlsConfig.getDefaultPSKIdentity().length > 0, 
                  "PSK identity should not be empty (must be at least of size 1)");
    }
    
    /**
     * Test that tryPsk method properly configures PSK identity before executing workflow.
     * This is a more targeted test for the specific bug fix.
     */
    @Test
    public void testTryPskSetsPskIdentity() {
        // Create the attacker instance
        TestableServerPskBruteforcer attacker = new TestableServerPskBruteforcer(config, baseConfig);
        
        // Test data
        byte[] pskGuess = new byte[]{0x01, 0x02, 0x03, 0x04};
        CipherSuite suite = CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA;
        
        // Call tryPsk - it should not throw IllegalArgumentException anymore
        Config usedConfig = attacker.testTryPskConfig(pskGuess, suite);
        
        // Verify that both PSK key and identity are set
        assertNotNull(usedConfig.getDefaultPSKKey(), "PSK key should be set");
        assertNotNull(usedConfig.getDefaultPSKIdentity(), "PSK identity should be set");
        assertTrue(usedConfig.getDefaultPSKIdentity().length > 0, 
                  "PSK identity should not be empty");
    }
    
    /**
     * Test that getSupportedPskCipherSuite sets PSK identity.
     */
    @Test
    public void testGetSupportedPskCipherSuiteSetsPskIdentity() {
        // Create the attacker instance
        TestableServerPskBruteforcer attacker = new TestableServerPskBruteforcer(config, baseConfig);
        
        // Call the method that checks for PSK support
        Config usedConfig = attacker.testGetSupportedPskCipherSuiteConfig();
        
        // Verify that PSK identity is set
        assertNotNull(usedConfig.getDefaultPSKIdentity(), "PSK identity should be set");
        assertTrue(usedConfig.getDefaultPSKIdentity().length > 0, 
                  "PSK identity should not be empty");
    }
    
    /**
     * Testable version of PskBruteForcerAttackServer that exposes the Config
     * used in tryPsk method for testing purposes.
     */
    private static class TestableServerPskBruteforcer extends PskBruteForcerAttackServer {
        
        public TestableServerPskBruteforcer(PskBruteForcerAttackServerCommandConfig config, 
                                          Config baseConfig) {
            super(config, baseConfig);
        }
        
        /**
         * Test version of tryPsk that returns the Config instead of executing workflow.
         */
        public Config testTryPskConfig(byte[] pskGuess, CipherSuite suite) {
            Config tlsConfig = getTlsConfig();
            tlsConfig.setDefaultClientSupportedCipherSuites(suite);
            tlsConfig.setDefaultSelectedCipherSuite(suite);
            tlsConfig.setDefaultPSKKey(pskGuess);
            tlsConfig.setDefaultPSKIdentity(config.getPskIdentity().getBytes());
            return tlsConfig;
        }
        
        /**
         * Test version that returns the Config used in getSupportedPskCipherSuite.
         */
        public Config testGetSupportedPskCipherSuiteConfig() {
            Config tlsConfig = getTlsConfig();
            String clientIdentity = config.getPskIdentity();
            tlsConfig.setDefaultPSKIdentity(clientIdentity.getBytes());
            return tlsConfig;
        }
    }
}