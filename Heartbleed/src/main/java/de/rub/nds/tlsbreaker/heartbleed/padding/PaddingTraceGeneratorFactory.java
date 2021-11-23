/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.heartbleed.padding;

import de.rub.nds.tlsbreaker.heartbleed.config.PaddingOracleCommandConfig;

/**
 *
 *
 */
public class PaddingTraceGeneratorFactory {

    /**
     *
     * @param  config
     * @return
     */
    public static PaddingTraceGenerator getPaddingTraceGenerator(PaddingOracleCommandConfig config) {
        switch (config.getVectorGeneratorType()) {
            case CLASSIC:
                return new ClassicPaddingTraceGenerator(config.getRecordGeneratorType());
            case FINISHED:
                return new FinishedPaddingTraceGenerator(config.getRecordGeneratorType());
            case FINISHED_RESUMPTION:
                return new FinishedResumptionPaddingTraceGenerator(config.getRecordGeneratorType());
            case CLOSE_NOTIFY:
                return new ClassicCloseNotifyTraceGenerator(config.getRecordGeneratorType());
            case CLASSIC_DYNAMIC:
                return new ClassicDynamicPaddingTraceGenerator(config.getRecordGeneratorType());
            case HEARTBEAT:
                return new HeartbeatPaddingTraceGenerator(config.getRecordGeneratorType());
            default:
                throw new IllegalArgumentException("Unknown PaddingTraceGenerator: " + config.getVectorGeneratorType());
        }
    }

    private PaddingTraceGeneratorFactory() {
    }
}
