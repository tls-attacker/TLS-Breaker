/**
 * TLS-Breaker - A tool collection of various attacks on TLS based on TLS-Attacker
 *
 * Copyright 2021-2022 Ruhr University Bochum, Paderborn University, Hackmanit GmbH
 *
 * Licensed under Apache License, Version 2.0
 * http://www.apache.org/licenses/LICENSE-2.0.txt
 */

package de.rub.nds.tlsbreaker.invalidcurve.ec;

import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.crypto.ec.CurveFactory;
import de.rub.nds.tlsattacker.core.crypto.ec.EllipticCurve;
import de.rub.nds.tlsattacker.core.crypto.ec.Point;
import java.math.BigInteger;
import java.util.List;
import java.util.stream.Stream;
import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class ICEPointReaderTest {

    public static Stream<Arguments> provideNamedGroups() {
        return Stream.of(NamedGroup.BRAINPOOLP256R1, NamedGroup.BRAINPOOLP384R1, NamedGroup.BRAINPOOLP512R1,
            NamedGroup.SECP160K1, NamedGroup.SECP160R1, NamedGroup.SECP160R2, NamedGroup.SECP192K1,
            NamedGroup.SECP192R1, NamedGroup.SECP224K1, NamedGroup.SECP224R1, NamedGroup.SECP256R1,
            NamedGroup.SECP384R1, NamedGroup.SECP521R1).map(Arguments::of);
    }

    @ParameterizedTest
    @MethodSource("provideNamedGroups")
    public void testPointsCorrectness(NamedGroup providedNamedGroup) {
        List<ICEPoint> invalidPoints = ICEPointReader.readPoints(providedNamedGroup);
        EllipticCurve curve = CurveFactory.getCurve(providedNamedGroup);
        for (ICEPoint invalidPoint : invalidPoints) {
            int order = invalidPoint.getOrder();
            // if we multiply the point by (order+1), we should get the same point
            Point result = curve.mult(BigInteger.valueOf(order + 1), invalidPoint);
            assertEquals(result.getFieldX(), invalidPoint.getFieldX());
            assertEquals(result.getFieldY(), invalidPoint.getFieldY());
        }
    }
}
