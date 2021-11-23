/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2021 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.clientpskbruteforcer.padding;

import de.rub.nds.tlsbreaker.clientpskbruteforcer.constants.PaddingRecordGeneratorType;
import de.rub.nds.tlsbreaker.clientpskbruteforcer.padding.vector.PaddingVector;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.workflow.WorkflowTrace;

/**
 *
 *
 */
public abstract class PaddingTraceGenerator {

    /**
     *
     */
    protected final PaddingVectorGenerator vectorGenerator;

    /**
     *
     * @param type
     */
    public PaddingTraceGenerator(PaddingRecordGeneratorType type) {
        switch (type) {
            case LONG_RECORD:
                vectorGenerator = new LongRecordPaddingGenerator();
                break;
            case LONG:
                vectorGenerator = new LongPaddingGenerator();
                break;
            case MEDIUM:
                vectorGenerator = new MediumPaddingGenerator();
                break;
            case SHORT:
                vectorGenerator = new ShortPaddingGenerator();
                break;
            case VERY_SHORT:
                vectorGenerator = new VeryShortPaddingGenerator();
                break;
            default:
                throw new IllegalArgumentException("Unknown RecordGenerator Type");
        }

    }

    /**
     *
     * @param  config
     * @param  vector
     * @return
     */
    public abstract WorkflowTrace getPaddingOracleWorkflowTrace(Config config, PaddingVector vector);

    public PaddingVectorGenerator getVectorGenerator() {
        return vectorGenerator;
    }
}
